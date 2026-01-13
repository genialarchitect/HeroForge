//! UK NCSC Cyber Essentials Controls
//!
//! Cyber Essentials is a UK government-backed certification scheme that helps
//! organizations protect themselves against a wide range of the most common
//! cyber attacks. This module covers both Cyber Essentials and Cyber Essentials Plus.
//!
//! The 5 Technical Control Themes:
//! 1. Firewalls - Boundary firewalls and internet gateways
//! 2. Secure Configuration - Secure configuration of devices and software
//! 3. User Access Control - Access control and administrative privilege management
//! 4. Malware Protection - Malware protection mechanisms
//! 5. Patch Management - Security update management
//!
//! Cyber Essentials Plus adds verified testing by an accredited assessor including:
//! - External vulnerability scanning
//! - Internal vulnerability assessment
//! - Verified malware protection testing
//! - Sample-based configuration reviews

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of Cyber Essentials controls in this module
pub const CONTROL_COUNT: usize = 42;

/// Get all Cyber Essentials controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // ============================================================
        // Theme 1: FIREWALLS (Boundary firewalls and internet gateways)
        // ============================================================
        ComplianceControl {
            id: "CE-FW-01".to_string(),
            control_id: "FW-01".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Boundary Firewall Deployment".to_string(),
            description: "A firewall (or equivalent network device) must be deployed at the boundary between the organization's internal network and the internet.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.4".to_string(), "NIST-SC-7".to_string(), "PCI-DSS-1.1".to_string()],
            remediation_guidance: Some("Deploy a hardware or software firewall at the network boundary. Ensure all traffic between internal networks and the internet passes through the firewall.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-02".to_string(),
            control_id: "FW-02".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Default Deny Inbound Traffic".to_string(),
            description: "The firewall must be configured to block all inbound connections by default, only allowing explicitly authorized services.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("CE-FW-01".to_string()),
            cross_references: vec!["CIS-4.4".to_string(), "NIST-SC-7".to_string()],
            remediation_guidance: Some("Configure firewall rules with a default deny policy for inbound traffic. Create explicit allow rules only for required services.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-03".to_string(),
            control_id: "FW-03".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Firewall Rule Documentation".to_string(),
            description: "Firewall rules allowing inbound connections must be documented and approved by an authorized individual.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("CE-FW-01".to_string()),
            cross_references: vec!["PCI-DSS-1.1.1".to_string()],
            remediation_guidance: Some("Maintain documentation of all firewall rules including business justification, owner, and approval date. Review rules at least annually.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-04".to_string(),
            control_id: "FW-04".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Remove Unnecessary Firewall Rules".to_string(),
            description: "Firewall rules that are no longer needed must be removed or disabled.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CE-FW-01".to_string()),
            cross_references: vec!["CIS-4.4".to_string()],
            remediation_guidance: Some("Conduct regular reviews of firewall rules (at least annually) to identify and remove rules that are no longer required.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-05".to_string(),
            control_id: "FW-05".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Host-Based Firewall on End-User Devices".to_string(),
            description: "Host-based firewalls or equivalent protection must be enabled on all end-user devices.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.5".to_string(), "NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable Windows Firewall, iptables, or equivalent host-based firewall on all workstations and laptops. Configure default deny policy for inbound connections.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-06".to_string(),
            control_id: "FW-06".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Host-Based Firewall on Servers".to_string(),
            description: "Host-based firewalls must be enabled on all servers, blocking unnecessary inbound connections.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.4".to_string(), "NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable and configure host-based firewalls on all servers. Only allow connections to required services.".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-07".to_string(),
            control_id: "FW-07".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Firewall Administrative Access Control".to_string(),
            description: "Administrative interfaces on firewalls and routers must only be accessible to authorized administrators.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("CE-FW-01".to_string()),
            cross_references: vec!["CIS-4.6".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Restrict firewall management access to specific IP addresses or management networks. Use strong authentication and encrypted protocols (SSH, HTTPS).".to_string()),
        },
        ComplianceControl {
            id: "CE-FW-08".to_string(),
            control_id: "FW-08".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Change Default Firewall Credentials".to_string(),
            description: "Default passwords on firewalls and routers must be changed before deployment.".to_string(),
            category: "Firewalls".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("CE-FW-01".to_string()),
            cross_references: vec!["CIS-4.7".to_string(), "PCI-DSS-2.1".to_string()],
            remediation_guidance: Some("Change all default passwords on network devices immediately upon deployment. Use strong, unique passwords for each device.".to_string()),
        },

        // ============================================================
        // Theme 2: SECURE CONFIGURATION
        // ============================================================
        ComplianceControl {
            id: "CE-SC-01".to_string(),
            control_id: "SC-01".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Remove Unnecessary Software".to_string(),
            description: "Unnecessary software and applications must be removed from all devices.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-2.3".to_string(), "NIST-CM-7".to_string()],
            remediation_guidance: Some("Conduct software inventory and remove applications not required for business purposes. Maintain an approved software list.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-02".to_string(),
            control_id: "SC-02".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Disable Unnecessary Services".to_string(),
            description: "Unnecessary services and network protocols must be disabled on all devices.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.2".to_string(), "NIST-CM-7".to_string()],
            remediation_guidance: Some("Identify and disable services not required for device function. This includes network services, background applications, and startup programs.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-03".to_string(),
            control_id: "SC-03".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Disable Autorun for Removable Media".to_string(),
            description: "Autorun must be disabled for removable media on all devices.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-10.3".to_string(), "NIST-MP-7".to_string()],
            remediation_guidance: Some("Configure Group Policy or system settings to disable autorun/autoplay functionality for USB drives, CDs, and other removable media.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-04".to_string(),
            control_id: "SC-04".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Change Default Passwords".to_string(),
            description: "Default passwords on all devices and software must be changed to strong, unique passwords.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.7".to_string(), "CIS-5.2".to_string(), "PCI-DSS-2.1".to_string()],
            remediation_guidance: Some("Identify all default accounts and change their passwords. Use passwords with at least 12 characters including mixed case, numbers, and special characters.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-05".to_string(),
            control_id: "SC-05".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Disable or Rename Default Accounts".to_string(),
            description: "Default user accounts that are not needed must be disabled or renamed.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.7".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Disable guest accounts and rename administrator accounts where possible. Create individual named accounts for administrative access.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-06".to_string(),
            control_id: "SC-06".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Account Lockout Policy".to_string(),
            description: "User accounts must lock after a maximum of 10 unsuccessful login attempts.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "PCI-DSS-8.1.6".to_string()],
            remediation_guidance: Some("Configure account lockout policy to lock accounts after 10 failed attempts. Implement lockout duration of at least 30 minutes or require administrator unlock.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-07".to_string(),
            control_id: "SC-07".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Password Complexity Requirements".to_string(),
            description: "Password policies must enforce minimum complexity requirements.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.2".to_string(), "NIST-IA-5".to_string(), "PCI-DSS-8.2".to_string()],
            remediation_guidance: Some("Configure password policy requiring minimum 12 characters, or 8 characters with MFA enabled. Implement password history to prevent reuse.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-08".to_string(),
            control_id: "SC-08".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Session Timeout Configuration".to_string(),
            description: "Devices must be configured to automatically lock after a period of inactivity.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-4.3".to_string(), "NIST-AC-11".to_string()],
            remediation_guidance: Some("Configure screen lock to activate after 15 minutes or less of inactivity. Require authentication to unlock.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-09".to_string(),
            control_id: "SC-09".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Secure Browser Configuration".to_string(),
            description: "Web browsers must be configured securely with plugins and extensions minimized.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-9.1".to_string()],
            remediation_guidance: Some("Use only supported browsers. Remove unnecessary plugins and extensions. Configure browsers to block pop-ups and warn about malicious sites.".to_string()),
        },
        ComplianceControl {
            id: "CE-SC-10".to_string(),
            control_id: "SC-10".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Disable Macro Execution".to_string(),
            description: "Macros must be disabled by default in office applications, or limited to trusted sources.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Configure Group Policy to disable macros in Microsoft Office applications or limit execution to digitally signed macros from trusted publishers.".to_string()),
        },

        // ============================================================
        // Theme 3: USER ACCESS CONTROL
        // ============================================================
        ComplianceControl {
            id: "CE-AC-01".to_string(),
            control_id: "AC-01".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "User Account Management Process".to_string(),
            description: "A process must exist for creating, approving, and removing user accounts.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["CIS-5.1".to_string(), "CIS-6.1".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Document procedures for requesting, approving, and provisioning user accounts. Include procedures for timely removal when users leave.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-02".to_string(),
            control_id: "AC-02".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Unique User Accounts".to_string(),
            description: "Each user must have a unique account; shared accounts must not be used.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.1".to_string(), "NIST-AC-2".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Create individual user accounts for all users. Eliminate shared or generic accounts. Implement audit logging tied to individual accounts.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-03".to_string(),
            control_id: "AC-03".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Least Privilege Principle".to_string(),
            description: "User accounts must be given the minimum privileges necessary to perform their role.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.4".to_string(), "NIST-AC-6".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Review user permissions and remove unnecessary access rights. Implement role-based access control aligned with job functions.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-04".to_string(),
            control_id: "AC-04".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Separate Administrator Accounts".to_string(),
            description: "Administrative privileges must not be used for day-to-day activities; separate accounts must be used.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.4".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Create separate administrator accounts for privileged activities. Users should use standard accounts for email, web browsing, and general work.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-05".to_string(),
            control_id: "AC-05".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Limit Administrative Accounts".to_string(),
            description: "The number of accounts with administrative privileges must be minimized.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CE-AC-04".to_string()),
            cross_references: vec!["CIS-5.4".to_string(), "NIST-AC-6".to_string()],
            remediation_guidance: Some("Audit administrative accounts regularly. Remove unnecessary admin rights. Maintain a documented list of all privileged accounts with business justification.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-06".to_string(),
            control_id: "AC-06".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Remove Unnecessary User Accounts".to_string(),
            description: "User accounts that are no longer required must be disabled or removed promptly.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-5.3".to_string(), "CIS-6.2".to_string(), "NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement automated account deprovisioning when users leave. Conduct regular reviews to identify and disable dormant accounts.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-07".to_string(),
            control_id: "AC-07".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Authentication for All Users".to_string(),
            description: "All user access to devices and services must require authentication.".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-6.3".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Ensure all systems require user authentication. Disable anonymous access. Configure services to require credentials before granting access.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-08".to_string(),
            control_id: "AC-08".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Multi-Factor Authentication for Remote Access".to_string(),
            description: "Multi-factor authentication should be used for remote access and cloud services (required for Cyber Essentials Plus).".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-6.4".to_string(), "NIST-IA-2".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Implement MFA for VPN, remote desktop, cloud services, and any internet-facing applications. Use authenticator apps or hardware tokens.".to_string()),
        },
        ComplianceControl {
            id: "CE-AC-09".to_string(),
            control_id: "AC-09".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Multi-Factor Authentication for Admin Access".to_string(),
            description: "Multi-factor authentication must be used for administrative access (required for Cyber Essentials Plus).".to_string(),
            category: "User Access Control".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-6.5".to_string(), "NIST-IA-2".to_string()],
            remediation_guidance: Some("Enable MFA for all administrative accounts across all systems. This includes domain admin, local admin, and service admin accounts.".to_string()),
        },

        // ============================================================
        // Theme 4: MALWARE PROTECTION
        // ============================================================
        ComplianceControl {
            id: "CE-MP-01".to_string(),
            control_id: "MP-01".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Anti-Malware Software Deployment".to_string(),
            description: "Anti-malware software must be installed on all devices capable of running it.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-10.1".to_string(), "NIST-SI-3".to_string(), "PCI-DSS-5.1".to_string()],
            remediation_guidance: Some("Deploy anti-malware software on all Windows, macOS, and Linux endpoints. Ensure coverage includes workstations, laptops, and servers.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-02".to_string(),
            control_id: "MP-02".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Anti-Malware Automatic Updates".to_string(),
            description: "Anti-malware software must be configured to update automatically.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("CE-MP-01".to_string()),
            cross_references: vec!["CIS-10.2".to_string(), "NIST-SI-3".to_string(), "PCI-DSS-5.2".to_string()],
            remediation_guidance: Some("Configure anti-malware to update definitions at least daily. Enable automatic updates and verify update mechanism is functioning.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-03".to_string(),
            control_id: "MP-03".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Real-Time Malware Scanning".to_string(),
            description: "Anti-malware software must be configured for real-time (on-access) scanning.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: Some("CE-MP-01".to_string()),
            cross_references: vec!["CIS-10.1".to_string(), "NIST-SI-3".to_string()],
            remediation_guidance: Some("Enable real-time protection to scan files as they are accessed, downloaded, or executed. Do not rely solely on scheduled scans.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-04".to_string(),
            control_id: "MP-04".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Web Content Scanning".to_string(),
            description: "Web content must be scanned for malware before being downloaded or executed.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-9.2".to_string(), "NIST-SI-3".to_string()],
            remediation_guidance: Some("Enable web filtering and scanning capabilities. Use browser security features and web proxies to scan downloads.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-05".to_string(),
            control_id: "MP-05".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Email Malware Scanning".to_string(),
            description: "Email attachments and links must be scanned for malware.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "NIST-SI-8".to_string()],
            remediation_guidance: Some("Implement email security gateway scanning or ensure email client anti-malware integration. Scan attachments before delivery.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-06".to_string(),
            control_id: "MP-06".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Application Whitelisting".to_string(),
            description: "Application whitelisting should be used to prevent unauthorized software execution (alternative to traditional AV).".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-2.5".to_string(), "NIST-CM-7".to_string()],
            remediation_guidance: Some("Implement application whitelisting using Windows AppLocker, macOS Gatekeeper, or third-party solutions to allow only approved applications.".to_string()),
        },
        ComplianceControl {
            id: "CE-MP-07".to_string(),
            control_id: "MP-07".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Sandboxing High-Risk Content".to_string(),
            description: "High-risk content such as downloaded files should be opened in sandbox environments where possible.".to_string(),
            category: "Malware Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Use browser sandboxing, Windows Sandbox, or third-party sandbox solutions to isolate potentially malicious content.".to_string()),
        },

        // ============================================================
        // Theme 5: PATCH MANAGEMENT
        // ============================================================
        ComplianceControl {
            id: "CE-PM-01".to_string(),
            control_id: "PM-01".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Operating System Patch Management".to_string(),
            description: "Operating systems must be patched within 14 days of patch release for high/critical vulnerabilities.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.3".to_string(), "NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Implement automated patch management for operating systems. Configure Windows Update, apt-get, or equivalent for automatic updates.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-02".to_string(),
            control_id: "PM-02".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Application Patch Management".to_string(),
            description: "Applications must be patched within 14 days of patch release for high/critical vulnerabilities.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.4".to_string(), "NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Enable automatic updates for applications where possible. Use patch management tools for enterprise application deployment.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-03".to_string(),
            control_id: "PM-03".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Firmware Update Management".to_string(),
            description: "Firmware on network devices and hardware must be kept up to date.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-12.1".to_string(), "NIST-SI-2".to_string()],
            remediation_guidance: Some("Monitor firmware updates from vendors. Apply firmware patches within 14 days for critical vulnerabilities.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-04".to_string(),
            control_id: "PM-04".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Supported Software Only".to_string(),
            description: "Only software that is currently supported by the vendor must be used.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-2.2".to_string(), "NIST-SA-22".to_string()],
            remediation_guidance: Some("Maintain inventory of software end-of-life dates. Plan upgrades before support ends. Remove unsupported software from the environment.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-05".to_string(),
            control_id: "PM-05".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Browser and Plugin Updates".to_string(),
            description: "Web browsers and browser plugins must be kept up to date.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-9.1".to_string(), "NIST-SI-2".to_string()],
            remediation_guidance: Some("Enable automatic updates for browsers. Remove unnecessary plugins. Update remaining plugins within 14 days of patch release.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-06".to_string(),
            control_id: "PM-06".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Vulnerability Scanning".to_string(),
            description: "Regular vulnerability scanning must be performed to identify missing patches (required for Cyber Essentials Plus).".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.5".to_string(), "CIS-7.6".to_string(), "NIST-RA-5".to_string()],
            remediation_guidance: Some("Perform internal and external vulnerability scans at least quarterly. Address critical vulnerabilities within 14 days.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-07".to_string(),
            control_id: "PM-07".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Patch Testing Process".to_string(),
            description: "A process should exist to test patches before deployment to production systems.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string()],
            remediation_guidance: Some("Establish a patch testing environment. Test patches on non-production systems before broad deployment. Document patch testing procedures.".to_string()),
        },
        ComplianceControl {
            id: "CE-PM-08".to_string(),
            control_id: "PM-08".to_string(),
            framework: ComplianceFramework::CyberEssentials,
            title: "Patch Status Reporting".to_string(),
            description: "Patch status must be monitored and reported to track compliance.".to_string(),
            category: "Patch Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["CIS-7.7".to_string(), "NIST-SI-2".to_string()],
            remediation_guidance: Some("Implement patch management reporting. Track patch compliance rates and aging. Report on systems missing critical patches.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant Cyber Essentials controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // ============================================================
    // Firewall-related vulnerabilities
    // ============================================================
    if title_lower.contains("firewall")
        || title_lower.contains("open port")
        || title_lower.contains("exposed service")
        || title_lower.contains("unnecessary port")
    {
        mappings.push(("CE-FW-01".to_string(), Severity::High));
        mappings.push(("CE-FW-02".to_string(), Severity::High));
        mappings.push(("CE-FW-04".to_string(), Severity::Medium));
    }

    // Administrative interface exposure
    if title_lower.contains("admin interface")
        || title_lower.contains("management interface")
        || title_lower.contains("remote management")
    {
        mappings.push(("CE-FW-07".to_string(), Severity::High));
    }

    // Common management ports exposed
    if let Some(p) = port {
        match p {
            22 | 23 | 3389 | 5900 | 5901 => {
                if title_lower.contains("exposed") || title_lower.contains("internet") {
                    mappings.push(("CE-FW-02".to_string(), Severity::High));
                    mappings.push(("CE-AC-08".to_string(), Severity::High));
                }
            }
            80 | 443 | 8080 | 8443 => {
                if title_lower.contains("admin") || title_lower.contains("management") {
                    mappings.push(("CE-FW-07".to_string(), Severity::High));
                }
            }
            _ => {}
        }
    }

    // Telnet (insecure protocol)
    if port == Some(23) || title_lower.contains("telnet") {
        mappings.push(("CE-SC-02".to_string(), Severity::High));
        mappings.push(("CE-FW-02".to_string(), Severity::High));
    }

    // ============================================================
    // Secure Configuration vulnerabilities
    // ============================================================
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
        || title_lower.contains("factory default")
        || title_lower.contains("default account")
    {
        mappings.push(("CE-SC-04".to_string(), Severity::Critical));
        mappings.push(("CE-FW-08".to_string(), Severity::Critical));
    }

    if title_lower.contains("weak password")
        || title_lower.contains("password complexity")
        || title_lower.contains("simple password")
    {
        mappings.push(("CE-SC-07".to_string(), Severity::High));
    }

    if title_lower.contains("account lockout")
        || title_lower.contains("brute force")
        || title_lower.contains("no lockout")
    {
        mappings.push(("CE-SC-06".to_string(), Severity::High));
    }

    if title_lower.contains("autorun")
        || title_lower.contains("autoplay")
        || title_lower.contains("removable media")
    {
        mappings.push(("CE-SC-03".to_string(), Severity::Medium));
    }

    if title_lower.contains("macro")
        || title_lower.contains("office macro")
        || title_lower.contains("vba")
    {
        mappings.push(("CE-SC-10".to_string(), Severity::High));
    }

    if title_lower.contains("session timeout")
        || title_lower.contains("screen lock")
        || title_lower.contains("idle timeout")
    {
        mappings.push(("CE-SC-08".to_string(), Severity::Low));
    }

    if title_lower.contains("unnecessary service")
        || title_lower.contains("unused service")
        || title_lower.contains("legacy service")
    {
        mappings.push(("CE-SC-02".to_string(), Severity::Medium));
    }

    if title_lower.contains("guest account")
        || title_lower.contains("anonymous access")
        || title_lower.contains("default user")
    {
        mappings.push(("CE-SC-05".to_string(), Severity::High));
    }

    // ============================================================
    // User Access Control vulnerabilities
    // ============================================================
    if title_lower.contains("excessive privilege")
        || title_lower.contains("admin privilege")
        || title_lower.contains("unnecessary permission")
    {
        mappings.push(("CE-AC-03".to_string(), Severity::High));
        mappings.push(("CE-AC-05".to_string(), Severity::High));
    }

    if title_lower.contains("shared account")
        || title_lower.contains("generic account")
        || title_lower.contains("service account misuse")
    {
        mappings.push(("CE-AC-02".to_string(), Severity::High));
    }

    if title_lower.contains("no mfa")
        || title_lower.contains("missing mfa")
        || title_lower.contains("without multi-factor")
        || title_lower.contains("single factor")
    {
        mappings.push(("CE-AC-08".to_string(), Severity::High));
        mappings.push(("CE-AC-09".to_string(), Severity::Critical));
    }

    if title_lower.contains("stale account")
        || title_lower.contains("dormant account")
        || title_lower.contains("inactive user")
    {
        mappings.push(("CE-AC-06".to_string(), Severity::Medium));
    }

    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
        || title_lower.contains("no authentication")
    {
        mappings.push(("CE-AC-07".to_string(), Severity::Critical));
    }

    // ============================================================
    // Malware Protection vulnerabilities
    // ============================================================
    if title_lower.contains("no antivirus")
        || title_lower.contains("missing endpoint protection")
        || title_lower.contains("no anti-malware")
        || title_lower.contains("disabled antivirus")
    {
        mappings.push(("CE-MP-01".to_string(), Severity::Critical));
    }

    if title_lower.contains("outdated signature")
        || title_lower.contains("antivirus out of date")
        || title_lower.contains("definition update")
    {
        mappings.push(("CE-MP-02".to_string(), Severity::High));
    }

    if title_lower.contains("real-time protection disabled")
        || title_lower.contains("on-access scanning")
    {
        mappings.push(("CE-MP-03".to_string(), Severity::High));
    }

    if title_lower.contains("malware")
        || title_lower.contains("virus")
        || title_lower.contains("trojan")
        || title_lower.contains("ransomware")
    {
        mappings.push(("CE-MP-01".to_string(), Severity::Critical));
        mappings.push(("CE-MP-03".to_string(), Severity::Critical));
    }

    // ============================================================
    // Patch Management vulnerabilities
    // ============================================================
    if title_lower.contains("outdated")
        || title_lower.contains("unpatched")
        || title_lower.contains("missing patch")
        || title_lower.contains("security update")
    {
        mappings.push(("CE-PM-01".to_string(), Severity::High));
        mappings.push(("CE-PM-02".to_string(), Severity::High));
    }

    if title_lower.contains("end of life")
        || title_lower.contains("unsupported")
        || title_lower.contains("eol")
        || title_lower.contains("no longer supported")
    {
        mappings.push(("CE-PM-04".to_string(), Severity::Critical));
    }

    if title_lower.contains("outdated browser")
        || title_lower.contains("browser vulnerability")
        || title_lower.contains("flash")
        || title_lower.contains("java plugin")
    {
        mappings.push(("CE-PM-05".to_string(), Severity::High));
        mappings.push(("CE-SC-09".to_string(), Severity::High));
    }

    if title_lower.contains("firmware")
        || title_lower.contains("bios")
        || title_lower.contains("uefi")
    {
        mappings.push(("CE-PM-03".to_string(), Severity::High));
    }

    // CVE-based mappings (any CVE indicates patching issues)
    if title_lower.contains("cve-") {
        mappings.push(("CE-PM-01".to_string(), Severity::High));
        mappings.push(("CE-PM-06".to_string(), Severity::Medium));
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
            assert_eq!(control.framework, ComplianceFramework::CyberEssentials);
        }
    }

    #[test]
    fn test_categories() {
        let controls = get_controls();
        let mut categories: Vec<String> = controls.iter().map(|c| c.category.clone()).collect();
        categories.sort();
        categories.dedup();

        // Should have 5 categories matching the 5 technical control themes
        assert!(categories.contains(&"Firewalls".to_string()));
        assert!(categories.contains(&"Secure Configuration".to_string()));
        assert!(categories.contains(&"User Access Control".to_string()));
        assert!(categories.contains(&"Malware Protection".to_string()));
        assert!(categories.contains(&"Patch Management".to_string()));
        assert_eq!(categories.len(), 5);
    }

    #[test]
    fn test_default_password_mapping() {
        let mappings = map_vulnerability("Default password detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CE-SC-04"));
    }

    #[test]
    fn test_outdated_software_mapping() {
        let mappings = map_vulnerability("Outdated Apache version", None, Some(80), Some("http"));
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CE-PM-01" || id == "CE-PM-02"));
    }

    #[test]
    fn test_missing_mfa_mapping() {
        let mappings = map_vulnerability("No MFA enabled for remote access", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CE-AC-08"));
    }

    #[test]
    fn test_missing_antivirus_mapping() {
        let mappings = map_vulnerability("No antivirus software detected", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CE-MP-01"));
    }

    #[test]
    fn test_eol_software_mapping() {
        let mappings = map_vulnerability("Windows 7 end of life - unsupported", None, None, None);
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|(id, _)| id == "CE-PM-04"));
    }

    #[test]
    fn test_control_ids_unique() {
        let controls = get_controls();
        let ids: Vec<&str> = controls.iter().map(|c| c.id.as_str()).collect();
        let mut unique_ids = ids.clone();
        unique_ids.sort();
        unique_ids.dedup();
        assert_eq!(ids.len(), unique_ids.len(), "Duplicate control IDs found");
    }

    #[test]
    fn test_critical_controls_exist() {
        let controls = get_controls();
        let critical_count = controls
            .iter()
            .filter(|c| matches!(c.priority, ControlPriority::Critical))
            .count();
        assert!(critical_count > 0, "Should have critical priority controls");
    }

    #[test]
    fn test_automated_checks() {
        let controls = get_controls();
        let automated_count = controls.iter().filter(|c| c.automated_check).count();
        // Most Cyber Essentials controls should be automatable
        assert!(
            automated_count > 30,
            "Expected more automated checks, found {}",
            automated_count
        );
    }
}
