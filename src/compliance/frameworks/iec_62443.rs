//! IEC 62443 Controls
//!
//! Industrial Automation and Control Systems (IACS) Security
//! This module contains controls based on IEC 62443 series standards covering:
//! - IEC 62443-1-1: General concepts
//! - IEC 62443-2-1: Policies and procedures
//! - IEC 62443-3-3: System security requirements (Security Levels 1-4)
//! - IEC 62443-4-2: Component security requirements
//!
//! Security Levels (SL):
//! - SL-1: Protection against casual or coincidental violation
//! - SL-2: Protection against intentional violation using simple means
//! - SL-3: Protection against sophisticated attack with moderate resources
//! - SL-4: Protection against state-sponsored attack with extensive resources
//!
//! Foundational Requirements (FR):
//! - FR 1: Identification and authentication control (IAC)
//! - FR 2: Use control (UC)
//! - FR 3: System integrity (SI)
//! - FR 4: Data confidentiality (DC)
//! - FR 5: Restricted data flow (RDF)
//! - FR 6: Timely response to events (TRE)
//! - FR 7: Resource availability (RA)

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of IEC 62443 controls in this module
pub const CONTROL_COUNT: usize = 67;

/// Get all IEC 62443 controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // FR 1: Identification and Authentication Control (IAC)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR1-SR1.1".to_string(),
            control_id: "SR 1.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Human User Identification and Authentication".to_string(),
            description: "Identify and authenticate all human users before allowing access to the control system. SL-1 requires basic authentication; SL-4 requires multi-factor authentication with hardware tokens.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-2".to_string(), "NIST-IA-2".to_string(), "CIS-6.3".to_string()],
            remediation_guidance: Some("Implement user authentication for all IACS access. For SL-3/4, deploy multi-factor authentication using hardware tokens or smart cards.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.2".to_string(),
            control_id: "SR 1.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Software Process and Device Identification and Authentication".to_string(),
            description: "Identify and authenticate all software processes and devices before allowing access. SL-2+ requires unique identification; SL-4 requires cryptographic authentication.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-3".to_string(), "NIST-IA-3".to_string()],
            remediation_guidance: Some("Implement device authentication using certificates or secure tokens. Configure mutual authentication for device-to-device communications.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.3".to_string(),
            control_id: "SR 1.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Account Management".to_string(),
            description: "Support management of all accounts including adding, activating, modifying, disabling, and removing accounts. SL-3+ requires automated account management.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-2".to_string(), "NIST-AC-2".to_string(), "CIS-5.1".to_string()],
            remediation_guidance: Some("Implement centralized account management with automated provisioning and deprovisioning workflows.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.4".to_string(),
            control_id: "SR 1.4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Identifier Management".to_string(),
            description: "Support management of identifiers by user, group, role, or control system interface. Prevent identifier reuse for a configurable time period.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-4".to_string(), "NIST-IA-4".to_string()],
            remediation_guidance: Some("Configure identifier management policies preventing reuse. Implement unique identifiers for all users and devices.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.5".to_string(),
            control_id: "SR 1.5".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Authenticator Management".to_string(),
            description: "Manage authenticators including initial distribution, lost/stolen replacement, revocation, and periodic refresh. SL-3+ requires hardware-based authenticators for privileged users.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-5".to_string(), "NIST-IA-5".to_string(), "CIS-5.2".to_string()],
            remediation_guidance: Some("Establish authenticator lifecycle management. Implement password complexity requirements and rotation policies.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.6".to_string(),
            control_id: "SR 1.6".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Wireless Access Management".to_string(),
            description: "Identify and authenticate all users engaged in wireless communication. SL-2+ requires encryption; SL-4 requires certificate-based authentication.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-18".to_string(), "NIST-AC-18".to_string()],
            remediation_guidance: Some("Implement WPA3-Enterprise or equivalent for wireless IACS networks. Use certificate-based authentication for SL-3/4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.7".to_string(),
            control_id: "SR 1.7".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Strength of Password-based Authentication".to_string(),
            description: "Enforce minimum password strength for password-based authentication. SL-1 requires 8 characters; SL-4 requires 16+ characters with complexity.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-5".to_string(), "NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password policies: minimum 12 characters, complexity requirements, and prevent common password usage.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.8".to_string(),
            control_id: "SR 1.8".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Public Key Infrastructure Certificates".to_string(),
            description: "Support PKI for certificate-based authentication. SL-3+ requires certificate validation including revocation checking.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-5".to_string(), "NIST-SC-17".to_string()],
            remediation_guidance: Some("Deploy PKI infrastructure for IACS authentication. Configure certificate revocation checking (OCSP or CRL).".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.9".to_string(),
            control_id: "SR 1.9".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Strength of Public Key Authentication".to_string(),
            description: "Use validated cryptographic mechanisms for public key authentication. SL-2+ requires 2048-bit RSA or equivalent; SL-4 requires 3072-bit or higher.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-13".to_string(), "NIST-SC-13".to_string()],
            remediation_guidance: Some("Configure minimum 2048-bit RSA keys or 256-bit ECC. Plan migration to quantum-resistant algorithms.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.10".to_string(),
            control_id: "SR 1.10".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Authenticator Feedback".to_string(),
            description: "Obscure authentication feedback to prevent shoulder surfing. Do not display passwords or provide specific error messages about authentication failures.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-6".to_string(), "NIST-IA-6".to_string()],
            remediation_guidance: Some("Configure all authentication interfaces to mask password entry and provide generic error messages.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.11".to_string(),
            control_id: "SR 1.11".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Unsuccessful Login Attempts".to_string(),
            description: "Enforce limits on consecutive unsuccessful authentication attempts. SL-1 requires lockout after 10 attempts; SL-4 requires lockout after 3 attempts.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-7".to_string(), "NIST-AC-7".to_string()],
            remediation_guidance: Some("Configure account lockout after 5 failed attempts with progressive delays. Implement alerting for lockout events.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.12".to_string(),
            control_id: "SR 1.12".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "System Use Notification".to_string(),
            description: "Display system use notification message before authentication. Include privacy and monitoring statements as required by policy.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-8".to_string(), "NIST-AC-8".to_string()],
            remediation_guidance: Some("Configure login banners on all IACS components with legal notice and authorized use statement.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR1-SR1.13".to_string(),
            control_id: "SR 1.13".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Access via Untrusted Networks".to_string(),
            description: "Monitor and control access via untrusted networks. SL-3+ requires explicit authorization and encrypted tunnels for all external access.".to_string(),
            category: "Identification and Authentication Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-17".to_string(), "NIST-AC-17".to_string()],
            remediation_guidance: Some("Implement VPN with multi-factor authentication for all remote access. Deploy jump servers for administrative access.".to_string()),
        },

        // ============================================================
        // FR 2: Use Control (UC)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR2-SR2.1".to_string(),
            control_id: "SR 2.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Authorization Enforcement".to_string(),
            description: "Enforce assigned privileges for all user access. SL-2+ requires role-based access control; SL-4 requires attribute-based access control.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-3".to_string(), "NIST-AC-3".to_string(), "CIS-3.3".to_string()],
            remediation_guidance: Some("Implement role-based access control with least privilege. Define and enforce authorization policies for all IACS functions.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.2".to_string(),
            control_id: "SR 2.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Wireless Use Control".to_string(),
            description: "Control and monitor wireless device connections. SL-3+ requires whitelist-based wireless device authorization.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-18".to_string(), "NIST-AC-18".to_string()],
            remediation_guidance: Some("Implement wireless access control with device whitelisting. Monitor for unauthorized wireless access points.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.3".to_string(),
            control_id: "SR 2.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Use Control for Portable and Mobile Devices".to_string(),
            description: "Control access from portable and mobile devices. SL-2+ requires device registration; SL-4 requires device health attestation.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-19".to_string(), "NIST-AC-19".to_string()],
            remediation_guidance: Some("Implement mobile device management (MDM) for all portable devices accessing IACS. Require device compliance checks.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.4".to_string(),
            control_id: "SR 2.4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Mobile Code".to_string(),
            description: "Control execution of mobile code. SL-2+ requires mobile code restrictions; SL-4 requires mobile code signing and verification.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-18".to_string(), "NIST-SC-18".to_string()],
            remediation_guidance: Some("Disable or restrict mobile code (ActiveX, Java applets, scripts) on IACS components. Implement code signing requirements.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.5".to_string(),
            control_id: "SR 2.5".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Session Lock".to_string(),
            description: "Automatically lock sessions after a period of inactivity. SL-1 requires 15-minute timeout; SL-4 requires 5-minute timeout.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-11".to_string(), "NIST-AC-11".to_string(), "CIS-4.3".to_string()],
            remediation_guidance: Some("Configure automatic session lock after 10 minutes of inactivity on all IACS workstations and HMIs.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.6".to_string(),
            control_id: "SR 2.6".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Remote Session Termination".to_string(),
            description: "Support termination of remote sessions by user and administrator. SL-3+ requires automatic termination of inactive remote sessions.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-12".to_string(), "NIST-AC-12".to_string()],
            remediation_guidance: Some("Configure automatic termination of remote sessions after 30 minutes of inactivity. Provide manual session termination capability.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.7".to_string(),
            control_id: "SR 2.7".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Concurrent Session Control".to_string(),
            description: "Limit concurrent sessions per user account. SL-2+ requires session limits; SL-4 limits to single session for privileged accounts.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-10".to_string(), "NIST-AC-10".to_string()],
            remediation_guidance: Some("Configure maximum concurrent session limits. Restrict privileged accounts to single concurrent session.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.8".to_string(),
            control_id: "SR 2.8".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Auditable Events".to_string(),
            description: "Generate audit records for defined security-relevant events. SL-2+ requires comprehensive event logging; SL-4 requires real-time event correlation.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-2".to_string(), "NIST-AU-2".to_string(), "CIS-8.2".to_string()],
            remediation_guidance: Some("Enable audit logging for authentication, authorization, configuration changes, and security events on all IACS components.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.9".to_string(),
            control_id: "SR 2.9".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Audit Storage Capacity".to_string(),
            description: "Allocate sufficient audit log storage. SL-2+ requires 90-day retention; SL-4 requires 1-year retention with offsite backup.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-4".to_string(), "NIST-AU-4".to_string(), "CIS-8.3".to_string()],
            remediation_guidance: Some("Configure log retention for minimum 90 days locally. Forward logs to centralized SIEM for long-term retention.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.10".to_string(),
            control_id: "SR 2.10".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Response to Audit Processing Failures".to_string(),
            description: "Define response to audit processing failures. SL-3+ requires alerting and fail-secure behavior when audit fails.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-5".to_string(), "NIST-AU-5".to_string()],
            remediation_guidance: Some("Configure alerts for audit system failures. Implement fail-secure behavior that restricts access when logging fails.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.11".to_string(),
            control_id: "SR 2.11".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Timestamps".to_string(),
            description: "Record timestamps in audit records. SL-2+ requires synchronized time; SL-4 requires cryptographically secured timestamps.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-8".to_string(), "NIST-AU-8".to_string(), "CIS-8.4".to_string()],
            remediation_guidance: Some("Configure NTP synchronization on all IACS components. Use authenticated NTP for SL-3/4 environments.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR2-SR2.12".to_string(),
            control_id: "SR 2.12".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Non-repudiation".to_string(),
            description: "Provide non-repudiation for defined actions. SL-3+ requires cryptographic proof of origin for configuration changes.".to_string(),
            category: "Use Control".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-10".to_string(), "NIST-AU-10".to_string()],
            remediation_guidance: Some("Implement digital signatures for critical configuration changes and operator actions in SL-3/4 environments.".to_string()),
        },

        // ============================================================
        // FR 3: System Integrity (SI)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR3-SR3.1".to_string(),
            control_id: "SR 3.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Communication Integrity".to_string(),
            description: "Protect integrity of transmitted information. SL-1 requires error detection; SL-4 requires cryptographic integrity verification.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-8".to_string(), "NIST-SC-8".to_string()],
            remediation_guidance: Some("Enable integrity checking for all IACS communications. Use TLS 1.2+ or industrial secure protocols (OPC UA Secure Channel).".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.2".to_string(),
            control_id: "SR 3.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Malicious Code Protection".to_string(),
            description: "Implement protection against malicious code. SL-2+ requires anti-malware; SL-4 requires application whitelisting.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-3".to_string(), "NIST-SI-3".to_string(), "CIS-10.1".to_string()],
            remediation_guidance: Some("Deploy industrial-grade anti-malware on IACS systems. Implement application whitelisting for critical systems.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.3".to_string(),
            control_id: "SR 3.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Functionality Verification".to_string(),
            description: "Verify security functions are operating correctly. SL-2+ requires periodic verification; SL-4 requires continuous monitoring.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-6".to_string(), "NIST-SI-6".to_string()],
            remediation_guidance: Some("Implement automated security control verification. Monitor security function status continuously.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.4".to_string(),
            control_id: "SR 3.4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Software and Information Integrity".to_string(),
            description: "Detect and report unauthorized changes to software and information. SL-2+ requires file integrity monitoring; SL-4 requires real-time integrity verification.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-7".to_string(), "NIST-SI-7".to_string()],
            remediation_guidance: Some("Deploy file integrity monitoring on all IACS systems. Alert on unauthorized changes to system files and configurations.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.5".to_string(),
            control_id: "SR 3.5".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Input Validation".to_string(),
            description: "Validate inputs to control systems. SL-2+ requires input validation; SL-4 requires input sanitization and range checking.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-10".to_string(), "NIST-SI-10".to_string()],
            remediation_guidance: Some("Implement input validation on all user inputs and protocol messages. Validate data types, ranges, and formats.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.6".to_string(),
            control_id: "SR 3.6".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Deterministic Output".to_string(),
            description: "Ensure deterministic output under defined failure conditions. Critical for safety-related systems.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-17".to_string()],
            remediation_guidance: Some("Configure fail-safe states for all safety-critical outputs. Test failure modes and document expected behavior.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.7".to_string(),
            control_id: "SR 3.7".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Error Handling".to_string(),
            description: "Handle and report errors without revealing sensitive information. SL-2+ requires sanitized error messages.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-11".to_string(), "NIST-SI-11".to_string()],
            remediation_guidance: Some("Configure error handling to log detailed errors internally while displaying generic messages to users.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.8".to_string(),
            control_id: "SR 3.8".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Session Integrity".to_string(),
            description: "Protect session integrity against replay and hijacking attacks. SL-2+ requires session tokens; SL-4 requires cryptographic session binding.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-23".to_string(), "NIST-SC-23".to_string()],
            remediation_guidance: Some("Implement secure session management with anti-replay mechanisms. Use cryptographic session binding for SL-3/4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR3-SR3.9".to_string(),
            control_id: "SR 3.9".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Protection of Audit Information".to_string(),
            description: "Protect audit information from unauthorized access, modification, and deletion. SL-3+ requires cryptographic protection of audit logs.".to_string(),
            category: "System Integrity".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-9".to_string(), "NIST-AU-9".to_string()],
            remediation_guidance: Some("Configure read-only audit log storage. Forward logs to protected central repository. Implement log signing for SL-3/4.".to_string()),
        },

        // ============================================================
        // FR 4: Data Confidentiality (DC)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR4-SR4.1".to_string(),
            control_id: "SR 4.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Information Confidentiality".to_string(),
            description: "Protect confidentiality of information at rest and in transit. SL-2+ requires encryption; SL-4 requires hardware-based encryption.".to_string(),
            category: "Data Confidentiality".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-28".to_string(), "NIST-SC-28".to_string(), "CIS-3.6".to_string()],
            remediation_guidance: Some("Enable encryption for sensitive data at rest and in transit. Use AES-256 for data at rest; TLS 1.2+ for data in transit.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR4-SR4.2".to_string(),
            control_id: "SR 4.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Information Persistence".to_string(),
            description: "Provide capability to purge information from shared resources. SL-2+ requires secure deletion; SL-4 requires cryptographic erasure.".to_string(),
            category: "Data Confidentiality".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-4".to_string(), "NIST-SC-4".to_string()],
            remediation_guidance: Some("Implement secure deletion procedures for sensitive data. Use cryptographic erasure for SL-4 environments.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR4-SR4.3".to_string(),
            control_id: "SR 4.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Use of Cryptography".to_string(),
            description: "Use validated cryptographic algorithms. SL-2+ requires industry-standard algorithms; SL-4 requires FIPS 140-2 validated modules.".to_string(),
            category: "Data Confidentiality".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-13".to_string(), "NIST-SC-13".to_string()],
            remediation_guidance: Some("Use only approved cryptographic algorithms (AES, SHA-256+, RSA 2048+). Disable weak algorithms and protocols.".to_string()),
        },

        // ============================================================
        // FR 5: Restricted Data Flow (RDF)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR5-SR5.1".to_string(),
            control_id: "SR 5.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Network Segmentation".to_string(),
            description: "Segment control system networks from non-control system networks. SL-2+ requires physical or logical segmentation; SL-4 requires defense-in-depth zoning.".to_string(),
            category: "Restricted Data Flow".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-7".to_string(), "NIST-SC-7".to_string(), "CIS-4.4".to_string()],
            remediation_guidance: Some("Implement Purdue Model network segmentation. Use firewalls and DMZs to separate IACS zones. Deploy data diodes for SL-4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR5-SR5.2".to_string(),
            control_id: "SR 5.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Zone Boundary Protection".to_string(),
            description: "Monitor and control communications at zone boundaries. SL-2+ requires boundary firewalls; SL-4 requires application-layer inspection.".to_string(),
            category: "Restricted Data Flow".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-7".to_string(), "NIST-SC-7".to_string()],
            remediation_guidance: Some("Deploy industrial firewalls at zone boundaries. Configure allow-list rules for permitted communications.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR5-SR5.3".to_string(),
            control_id: "SR 5.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "General Purpose Person-to-Person Communication Restrictions".to_string(),
            description: "Restrict general-purpose communication within control system network. SL-2+ restricts email/web browsing; SL-4 prohibits non-IACS traffic.".to_string(),
            category: "Restricted Data Flow".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-7".to_string(), "NIST-AC-4".to_string()],
            remediation_guidance: Some("Block general internet access from IACS networks. Restrict communications to required industrial protocols only.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR5-SR5.4".to_string(),
            control_id: "SR 5.4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Application Partitioning".to_string(),
            description: "Partition applications to separate security-critical functions. SL-3+ requires separate execution environments for critical functions.".to_string(),
            category: "Restricted Data Flow".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-2".to_string(), "NIST-SC-2".to_string()],
            remediation_guidance: Some("Separate security-critical applications from general processing. Use virtualization or containerization for isolation.".to_string()),
        },

        // ============================================================
        // FR 6: Timely Response to Events (TRE)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR6-SR6.1".to_string(),
            control_id: "SR 6.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Audit Log Accessibility".to_string(),
            description: "Provide read access to audit logs for authorized users. SL-2+ requires searchable logs; SL-4 requires automated log analysis.".to_string(),
            category: "Timely Response to Events".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-6".to_string(), "NIST-AU-6".to_string()],
            remediation_guidance: Some("Implement centralized log management with search capabilities. Deploy SIEM for automated analysis in SL-3/4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR6-SR6.2".to_string(),
            control_id: "SR 6.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Continuous Monitoring".to_string(),
            description: "Continuously monitor control system for security events. SL-2+ requires periodic monitoring; SL-4 requires real-time monitoring and alerting.".to_string(),
            category: "Timely Response to Events".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SI-4".to_string(), "NIST-SI-4".to_string()],
            remediation_guidance: Some("Deploy industrial IDS/IPS for network monitoring. Implement real-time alerting for security events.".to_string()),
        },

        // ============================================================
        // FR 7: Resource Availability (RA)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-FR7-SR7.1".to_string(),
            control_id: "SR 7.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Denial of Service Protection".to_string(),
            description: "Protect against denial of service attacks. SL-2+ requires basic DoS protection; SL-4 requires DDoS mitigation and traffic shaping.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-5".to_string(), "NIST-SC-5".to_string()],
            remediation_guidance: Some("Implement rate limiting and traffic filtering. Deploy redundant network paths. Configure resource limits on critical services.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.2".to_string(),
            control_id: "SR 7.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Resource Management".to_string(),
            description: "Manage system resources to ensure availability. SL-2+ requires resource monitoring; SL-4 requires automated resource management.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-6".to_string(), "NIST-SC-6".to_string()],
            remediation_guidance: Some("Monitor CPU, memory, disk, and network utilization. Configure alerts for resource exhaustion conditions.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.3".to_string(),
            control_id: "SR 7.3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Control System Backup".to_string(),
            description: "Maintain backups of control system configuration and data. SL-2+ requires periodic backups; SL-4 requires continuous replication.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CP-9".to_string(), "NIST-CP-9".to_string(), "CIS-11.2".to_string()],
            remediation_guidance: Some("Implement automated backups of IACS configurations. Test restoration procedures regularly. Store backups offline for SL-3/4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.4".to_string(),
            control_id: "SR 7.4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Control System Recovery and Reconstitution".to_string(),
            description: "Support recovery to known secure state. SL-2+ requires documented recovery procedures; SL-4 requires automated recovery.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CP-10".to_string(), "NIST-CP-10".to_string()],
            remediation_guidance: Some("Document and test recovery procedures. Maintain spare equipment for critical components. Implement automated failover for SL-4.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.5".to_string(),
            control_id: "SR 7.5".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Emergency Power".to_string(),
            description: "Provide emergency power for critical control system components. SL-2+ requires UPS; SL-4 requires redundant power with generator backup.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-PE-11".to_string(), "NIST-PE-11".to_string()],
            remediation_guidance: Some("Deploy UPS systems for all critical IACS components. Implement generator backup for extended outages.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.6".to_string(),
            control_id: "SR 7.6".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Network and Security Configuration Settings".to_string(),
            description: "Document and maintain network and security configurations. SL-2+ requires configuration management; SL-4 requires automated configuration compliance.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CM-6".to_string(), "NIST-CM-6".to_string(), "CIS-4.1".to_string()],
            remediation_guidance: Some("Document baseline configurations for all IACS components. Implement automated configuration compliance monitoring.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.7".to_string(),
            control_id: "SR 7.7".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Least Functionality".to_string(),
            description: "Configure systems to provide only essential capabilities. SL-2+ disables unnecessary services; SL-4 uses minimal hardened images.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CM-7".to_string(), "NIST-CM-7".to_string(), "CIS-4.7".to_string()],
            remediation_guidance: Some("Disable unnecessary services, protocols, and ports on all IACS components. Remove unused software and features.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-FR7-SR7.8".to_string(),
            control_id: "SR 7.8".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Control System Component Inventory".to_string(),
            description: "Maintain inventory of control system components. SL-2+ requires manual inventory; SL-4 requires automated discovery and tracking.".to_string(),
            category: "Resource Availability".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CM-8".to_string(), "NIST-CM-8".to_string(), "CIS-1.1".to_string()],
            remediation_guidance: Some("Implement automated asset discovery for IACS networks. Maintain CMDB with hardware, software, and firmware versions.".to_string()),
        },

        // ============================================================
        // Security Level Specific Requirements (SL-1 through SL-4)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-SL1-BASE".to_string(),
            control_id: "SL-1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Level 1 - Basic Protection".to_string(),
            description: "Baseline security protection against casual or coincidental violation. Requires basic identification, authentication, and access control.".to_string(),
            category: "Security Level Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-3.1".to_string()],
            remediation_guidance: Some("Implement unique user identification, basic password authentication, and simple access control. Deploy anti-malware protection.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-SL2-STANDARD".to_string(),
            control_id: "SL-2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Level 2 - Standard Protection".to_string(),
            description: "Protection against intentional violation using simple means with low resources. Requires strong authentication, encryption, and network segmentation.".to_string(),
            category: "Security Level Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-3.2".to_string()],
            remediation_guidance: Some("Implement strong password policies, network segmentation, encrypted communications, and comprehensive logging.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-SL3-ENHANCED".to_string(),
            control_id: "SL-3".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Level 3 - Enhanced Protection".to_string(),
            description: "Protection against sophisticated attacks with moderate resources and IACS-specific knowledge. Requires multi-factor authentication, defense-in-depth, and advanced monitoring.".to_string(),
            category: "Security Level Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-3.3".to_string()],
            remediation_guidance: Some("Implement MFA, PKI-based authentication, industrial IDS/IPS, advanced network segmentation with data diodes, and security operations center monitoring.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-SL4-CRITICAL".to_string(),
            control_id: "SL-4".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Level 4 - Critical Protection".to_string(),
            description: "Protection against state-sponsored attacks with extensive resources and deep IACS expertise. Requires hardware-based security, air-gapped networks, and continuous security operations.".to_string(),
            category: "Security Level Requirements".to_string(),
            priority: ControlPriority::Critical,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-3.4".to_string()],
            remediation_guidance: Some("Implement hardware security modules, air-gapped networks, tamper-evident equipment, 24/7 SOC monitoring, and formal security certification.".to_string()),
        },

        // ============================================================
        // Component Requirements (IEC 62443-4-2)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-CR1.1".to_string(),
            control_id: "CR 1.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Human User Identification and Authentication".to_string(),
            description: "Components shall identify and authenticate human users attempting access. Applies to PLCs, RTUs, DCS, HMIs, and other IACS devices.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IA-2".to_string()],
            remediation_guidance: Some("Configure user authentication on all IACS components. Disable anonymous and default accounts. Implement password complexity requirements.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-CR2.1".to_string(),
            control_id: "CR 2.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Authorization Enforcement".to_string(),
            description: "Components shall enforce authorization for all human user access. Role-based access control for operators, engineers, and administrators.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AC-3".to_string()],
            remediation_guidance: Some("Configure role-based access on IACS components. Define separate roles for operators, engineers, and administrators with appropriate permissions.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-CR3.1".to_string(),
            control_id: "CR 3.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Communication Integrity".to_string(),
            description: "Components shall protect integrity of communications with other components. Use industrial secure protocols where available.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-8".to_string()],
            remediation_guidance: Some("Enable secure communications on IACS components (OPC UA Security, Modbus/TCP with TLS, encrypted EtherNet/IP). Disable insecure protocols where possible.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-CR4.1".to_string(),
            control_id: "CR 4.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Information Confidentiality".to_string(),
            description: "Components shall protect confidentiality of information at rest and in transit when storing or transmitting sensitive data.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-28".to_string()],
            remediation_guidance: Some("Enable encryption for sensitive data storage and transmission on IACS components. Configure secure channels for engineering access.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-CR6.1".to_string(),
            control_id: "CR 6.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Audit Log Accessibility".to_string(),
            description: "Components shall provide access to audit logs for authorized users. Support log export to central management systems.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AU-6".to_string()],
            remediation_guidance: Some("Configure log export from IACS components to central syslog or SIEM. Enable component-level audit logging.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-CR7.1".to_string(),
            control_id: "CR 7.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Component Denial of Service Protection".to_string(),
            description: "Components shall maintain essential functions when subjected to denial of service conditions. Prioritize critical traffic.".to_string(),
            category: "Component Requirements".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-800-82-SC-5".to_string()],
            remediation_guidance: Some("Configure rate limiting on component interfaces. Enable traffic prioritization for critical control communications.".to_string()),
        },

        // ============================================================
        // Policies and Procedures (IEC 62443-2-1)
        // ============================================================
        ComplianceControl {
            id: "IEC62443-PP-4.2.1".to_string(),
            control_id: "4.2.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Management System".to_string(),
            description: "Establish and maintain an industrial automation security management system (CSMS) with defined policies, procedures, and responsibilities.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-PM-1".to_string(), "ISO27001-5.1".to_string()],
            remediation_guidance: Some("Develop comprehensive CSMS documentation including security policies, roles and responsibilities, and governance structure.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-PP-4.2.2".to_string(),
            control_id: "4.2.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Risk Assessment".to_string(),
            description: "Conduct security risk assessments for IACS systems including threat identification, vulnerability assessment, and risk evaluation.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-RA-3".to_string(), "NIST-RA-3".to_string()],
            remediation_guidance: Some("Perform annual IACS security risk assessments. Document threats, vulnerabilities, and countermeasures. Determine target security levels.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-PP-4.3.1".to_string(),
            control_id: "4.3.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Awareness Training".to_string(),
            description: "Provide security awareness training for all personnel with access to IACS systems. Include OT-specific security topics.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-AT-2".to_string(), "NIST-AT-2".to_string()],
            remediation_guidance: Some("Develop and deliver OT security awareness training. Include social engineering, physical security, and IACS-specific threats.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-PP-4.3.2".to_string(),
            control_id: "4.3.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Security Skills and Staffing".to_string(),
            description: "Ensure adequate cybersecurity skills and staffing for IACS protection. Define competency requirements for security roles.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-PM-13".to_string()],
            remediation_guidance: Some("Define IACS security competency requirements. Provide specialized OT security training for security personnel.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-PP-4.4.1".to_string(),
            control_id: "4.4.1".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Incident Response Plan".to_string(),
            description: "Develop and maintain incident response plans specific to IACS environments. Include procedures for OT-specific incidents.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-IR-8".to_string(), "NIST-IR-8".to_string()],
            remediation_guidance: Some("Develop OT-specific incident response procedures. Include coordination with operations, engineering, and safety teams.".to_string()),
        },
        ComplianceControl {
            id: "IEC62443-PP-4.4.2".to_string(),
            control_id: "4.4.2".to_string(),
            framework: ComplianceFramework::Iec62443,
            title: "Business Continuity Plan".to_string(),
            description: "Develop business continuity and disaster recovery plans for IACS systems. Include manual operation procedures.".to_string(),
            category: "Policies and Procedures".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-800-82-CP-2".to_string(), "NIST-CP-2".to_string()],
            remediation_guidance: Some("Document business continuity procedures for IACS failures. Include manual override procedures and recovery time objectives.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant IEC 62443 controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();
    let service_lower = service.map(|s| s.to_lowercase()).unwrap_or_default();

    // Authentication vulnerabilities
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("no authentication")
    {
        mappings.push(("IEC62443-FR1-SR1.1".to_string(), Severity::Critical));
        mappings.push(("IEC62443-FR1-SR1.2".to_string(), Severity::Critical));
        mappings.push(("IEC62443-CR1.1".to_string(), Severity::Critical));
    }

    // Weak password vulnerabilities
    if title_lower.contains("weak password")
        || title_lower.contains("default password")
        || title_lower.contains("default credentials")
        || title_lower.contains("hardcoded password")
    {
        mappings.push(("IEC62443-FR1-SR1.5".to_string(), Severity::Critical));
        mappings.push(("IEC62443-FR1-SR1.7".to_string(), Severity::High));
    }

    // Brute force / lockout issues
    if title_lower.contains("brute force")
        || title_lower.contains("no lockout")
        || title_lower.contains("account lockout")
    {
        mappings.push(("IEC62443-FR1-SR1.11".to_string(), Severity::High));
    }

    // Authorization / access control vulnerabilities
    if title_lower.contains("unauthorized access")
        || title_lower.contains("privilege escalation")
        || title_lower.contains("improper access control")
    {
        mappings.push(("IEC62443-FR2-SR2.1".to_string(), Severity::Critical));
        mappings.push(("IEC62443-CR2.1".to_string(), Severity::High));
    }

    // Encryption vulnerabilities
    if title_lower.contains("unencrypted")
        || title_lower.contains("cleartext")
        || title_lower.contains("plaintext")
        || title_lower.contains("weak encryption")
        || title_lower.contains("weak cipher")
    {
        mappings.push(("IEC62443-FR4-SR4.1".to_string(), Severity::High));
        mappings.push(("IEC62443-FR4-SR4.3".to_string(), Severity::High));
        mappings.push(("IEC62443-CR4.1".to_string(), Severity::High));
    }

    // TLS/SSL vulnerabilities
    if title_lower.contains("ssl") || title_lower.contains("tls") {
        if title_lower.contains("weak") || title_lower.contains("vulnerable") || title_lower.contains("expired") {
            mappings.push(("IEC62443-FR3-SR3.1".to_string(), Severity::High));
            mappings.push(("IEC62443-CR3.1".to_string(), Severity::High));
        }
    }

    // Integrity vulnerabilities
    if title_lower.contains("integrity")
        || title_lower.contains("tampering")
        || title_lower.contains("modification")
    {
        mappings.push(("IEC62443-FR3-SR3.1".to_string(), Severity::High));
        mappings.push(("IEC62443-FR3-SR3.4".to_string(), Severity::High));
    }

    // Malware / code execution vulnerabilities
    if title_lower.contains("malware")
        || title_lower.contains("code execution")
        || title_lower.contains("remote code")
        || title_lower.contains("rce")
    {
        mappings.push(("IEC62443-FR3-SR3.2".to_string(), Severity::Critical));
    }

    // Input validation vulnerabilities
    if title_lower.contains("injection")
        || title_lower.contains("sql injection")
        || title_lower.contains("command injection")
        || title_lower.contains("buffer overflow")
        || title_lower.contains("input validation")
    {
        mappings.push(("IEC62443-FR3-SR3.5".to_string(), Severity::Critical));
    }

    // Session vulnerabilities
    if title_lower.contains("session")
        || title_lower.contains("replay attack")
        || title_lower.contains("session hijack")
    {
        mappings.push(("IEC62443-FR3-SR3.8".to_string(), Severity::High));
    }

    // Network segmentation issues
    if title_lower.contains("network segmentation")
        || title_lower.contains("flat network")
        || title_lower.contains("no firewall")
    {
        mappings.push(("IEC62443-FR5-SR5.1".to_string(), Severity::Critical));
        mappings.push(("IEC62443-FR5-SR5.2".to_string(), Severity::High));
    }

    // Denial of service vulnerabilities
    if title_lower.contains("denial of service")
        || title_lower.contains("dos")
        || title_lower.contains("resource exhaustion")
    {
        mappings.push(("IEC62443-FR7-SR7.1".to_string(), Severity::High));
        mappings.push(("IEC62443-CR7.1".to_string(), Severity::High));
    }

    // Logging / audit vulnerabilities
    if title_lower.contains("no logging")
        || title_lower.contains("audit disabled")
        || title_lower.contains("missing audit")
    {
        mappings.push(("IEC62443-FR2-SR2.8".to_string(), Severity::Medium));
        mappings.push(("IEC62443-FR6-SR6.1".to_string(), Severity::Medium));
    }

    // Backup issues
    if title_lower.contains("backup")
        || title_lower.contains("no recovery")
    {
        mappings.push(("IEC62443-FR7-SR7.3".to_string(), Severity::Medium));
        mappings.push(("IEC62443-FR7-SR7.4".to_string(), Severity::Medium));
    }

    // Industrial protocol vulnerabilities (OT-specific)
    let ot_protocols = ["modbus", "dnp3", "opc", "bacnet", "profinet", "ethercat", "ethernet/ip", "s7", "fins"];
    for protocol in &ot_protocols {
        if title_lower.contains(protocol) || service_lower.contains(protocol) {
            if title_lower.contains("vulnerable") || title_lower.contains("unauth") || title_lower.contains("exploit") {
                mappings.push(("IEC62443-FR3-SR3.1".to_string(), Severity::Critical));
                mappings.push(("IEC62443-FR5-SR5.1".to_string(), Severity::Critical));
            }
        }
    }

    // Common OT ports
    match port {
        Some(502) => {  // Modbus
            if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
                mappings.push(("IEC62443-FR5-SR5.1".to_string(), Severity::Critical));
                mappings.push(("IEC62443-FR1-SR1.2".to_string(), Severity::High));
            }
        },
        Some(102) => {  // S7comm
            mappings.push(("IEC62443-CR3.1".to_string(), Severity::High));
        },
        Some(20000) | Some(44818) => {  // DNP3, EtherNet/IP
            if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
                mappings.push(("IEC62443-FR5-SR5.2".to_string(), Severity::High));
            }
        },
        Some(4840) | Some(4843) => {  // OPC UA
            if title_lower.contains("vulnerable") || title_lower.contains("insecure") {
                mappings.push(("IEC62443-CR3.1".to_string(), Severity::High));
            }
        },
        Some(47808) => {  // BACnet
            if title_lower.contains("vulnerable") || title_lower.contains("exposed") {
                mappings.push(("IEC62443-FR5-SR5.1".to_string(), Severity::High));
            }
        },
        _ => {}
    }

    // Remote access vulnerabilities
    if title_lower.contains("remote access")
        || title_lower.contains("vpn")
        || title_lower.contains("exposed to internet")
    {
        mappings.push(("IEC62443-FR1-SR1.13".to_string(), Severity::Critical));
    }

    // Wireless vulnerabilities
    if title_lower.contains("wireless")
        || title_lower.contains("wifi")
        || title_lower.contains("wi-fi")
    {
        mappings.push(("IEC62443-FR1-SR1.6".to_string(), Severity::High));
        mappings.push(("IEC62443-FR2-SR2.2".to_string(), Severity::High));
    }

    // Outdated / unpatched vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("end of life")
        || title_lower.contains("unsupported")
    {
        mappings.push(("IEC62443-FR7-SR7.7".to_string(), Severity::High));
    }

    // Configuration issues
    if title_lower.contains("misconfiguration")
        || title_lower.contains("default configuration")
        || title_lower.contains("insecure configuration")
    {
        mappings.push(("IEC62443-FR7-SR7.6".to_string(), Severity::Medium));
        mappings.push(("IEC62443-FR7-SR7.7".to_string(), Severity::Medium));
    }

    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_count() {
        let controls = get_controls();
        assert_eq!(controls.len(), CONTROL_COUNT, "Control count mismatch");
    }

    #[test]
    fn test_all_controls_have_cross_references() {
        let controls = get_controls();
        for control in controls {
            // Most IEC 62443 controls should have NIST 800-82 cross-references
            if control.category != "Security Level Requirements" && control.category != "Policies and Procedures" {
                assert!(
                    !control.cross_references.is_empty() || control.control_id.starts_with("SL-"),
                    "Control {} ({}) should have cross-references",
                    control.id,
                    control.title
                );
            }
        }
    }

    #[test]
    fn test_framework_assignment() {
        let controls = get_controls();
        for control in controls {
            assert_eq!(
                control.framework,
                ComplianceFramework::Iec62443,
                "Control {} should be IEC 62443 framework",
                control.id
            );
        }
    }

    #[test]
    fn test_vulnerability_mapping_authentication() {
        let mappings = map_vulnerability("Authentication bypass in PLC", None, None, None);
        assert!(!mappings.is_empty(), "Should map authentication bypass vulnerability");
        assert!(mappings.iter().any(|(id, _)| id.contains("SR1.1")));
    }

    #[test]
    fn test_vulnerability_mapping_modbus() {
        let mappings = map_vulnerability("Modbus protocol exposed", None, Some(502), Some("modbus"));
        assert!(!mappings.is_empty(), "Should map Modbus vulnerability");
    }

    #[test]
    fn test_vulnerability_mapping_network_segmentation() {
        let mappings = map_vulnerability("No network segmentation between IT and OT", None, None, None);
        assert!(!mappings.is_empty(), "Should map segmentation issue");
        assert!(mappings.iter().any(|(id, _)| id.contains("SR5.1")));
    }

    #[test]
    fn test_security_level_controls_exist() {
        let controls = get_controls();
        let sl_controls: Vec<_> = controls
            .iter()
            .filter(|c| c.category == "Security Level Requirements")
            .collect();
        assert_eq!(sl_controls.len(), 4, "Should have 4 security level controls (SL-1 through SL-4)");
    }

    #[test]
    fn test_foundational_requirements_coverage() {
        let controls = get_controls();
        let categories: std::collections::HashSet<_> = controls.iter().map(|c| c.category.as_str()).collect();

        // Verify all 7 Foundational Requirements are covered
        assert!(categories.contains("Identification and Authentication Control"), "FR1 should be covered");
        assert!(categories.contains("Use Control"), "FR2 should be covered");
        assert!(categories.contains("System Integrity"), "FR3 should be covered");
        assert!(categories.contains("Data Confidentiality"), "FR4 should be covered");
        assert!(categories.contains("Restricted Data Flow"), "FR5 should be covered");
        assert!(categories.contains("Timely Response to Events"), "FR6 should be covered");
        assert!(categories.contains("Resource Availability"), "FR7 should be covered");
    }
}
