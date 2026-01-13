//! DoD Security Technical Implementation Guides (STIGs)
//!
//! STIGs are configuration standards for DoD information systems and software.
//! They contain technical guidance to "lock down" systems that might otherwise
//! be vulnerable to malicious attack.
//!
//! This module organizes STIG controls by technology category:
//! - Operating Systems (Windows, Linux, macOS)
//! - Network Devices (Routers, Switches, Firewalls)
//! - Web Servers (Apache, IIS, Nginx)
//! - Databases (SQL Server, Oracle, PostgreSQL, MySQL)
//! - Applications (General, .NET, Java)
//! - Virtualization (VMware, Hyper-V)
//! - Cloud (AWS, Azure, GCP)
//!
//! Severity Categories (CAT):
//! - CAT I (High): Vulnerabilities that could result in loss of confidentiality,
//!   availability, or integrity. Directly exploitable.
//! - CAT II (Medium): Vulnerabilities that could result in loss of confidentiality,
//!   availability, or integrity. May be more difficult to exploit.
//! - CAT III (Low): Vulnerabilities that degrade measures to protect against
//!   loss of confidentiality, availability, or integrity.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};

/// Total number of STIG controls in this module
pub const CONTROL_COUNT: usize = 156;

/// STIG severity category
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StigCategory {
    /// CAT I - High severity, directly exploitable
    CatI,
    /// CAT II - Medium severity
    CatII,
    /// CAT III - Low severity
    CatIII,
}

impl StigCategory {
    pub fn to_priority(self) -> ControlPriority {
        match self {
            StigCategory::CatI => ControlPriority::Critical,
            StigCategory::CatII => ControlPriority::High,
            StigCategory::CatIII => ControlPriority::Medium,
        }
    }
}

/// Get all DoD STIG controls
pub fn get_controls() -> Vec<ComplianceControl> {
    let mut controls = Vec::with_capacity(CONTROL_COUNT);

    // Add controls by category
    controls.extend(get_general_controls());
    controls.extend(get_windows_controls());
    controls.extend(get_linux_controls());
    controls.extend(get_network_controls());
    controls.extend(get_web_server_controls());
    controls.extend(get_database_controls());
    controls.extend(get_application_controls());
    controls.extend(get_virtualization_controls());
    controls.extend(get_cloud_controls());

    controls
}

/// General STIG controls applicable across systems
fn get_general_controls() -> Vec<ComplianceControl> {
    vec![
        // Account Management
        ComplianceControl {
            id: "STIG-GEN-001".to_string(),
            control_id: "V-220706".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Accounts must be locked after three consecutive invalid logon attempts".to_string(),
            description: "By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing is reduced.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-7".to_string(), "CIS-5.5".to_string()],
            remediation_guidance: Some("Configure account lockout policy to lock accounts after 3 failed attempts for at least 15 minutes.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-002".to_string(),
            control_id: "V-220707".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must be at least 15 characters in length".to_string(),
            description: "The shorter the password, the easier it is for password-cracking tools to identify the password.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string(), "CIS-5.2".to_string()],
            remediation_guidance: Some("Configure password policy to require minimum 15 character passwords.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-003".to_string(),
            control_id: "V-220708".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must contain at least one uppercase character".to_string(),
            description: "Use of complex passwords increases the time and resources required to compromise the password.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password complexity to require uppercase characters.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-004".to_string(),
            control_id: "V-220709".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must contain at least one lowercase character".to_string(),
            description: "Use of complex passwords increases the time and resources required to compromise the password.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password complexity to require lowercase characters.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-005".to_string(),
            control_id: "V-220710".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must contain at least one numeric character".to_string(),
            description: "Use of complex passwords increases the time and resources required to compromise the password.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password complexity to require numeric characters.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-006".to_string(),
            control_id: "V-220711".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must contain at least one special character".to_string(),
            description: "Use of complex passwords increases the time and resources required to compromise the password.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password complexity to require special characters.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-007".to_string(),
            control_id: "V-220712".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Passwords must be changed at least every 60 days".to_string(),
            description: "Any password, no matter how complex, can eventually be cracked. Changing passwords periodically mitigates this risk.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure maximum password age to 60 days.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-008".to_string(),
            control_id: "V-220713".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Password history must be enforced (24 passwords remembered)".to_string(),
            description: "Password history ensures users cannot reuse recent passwords, forcing the creation of new unique passwords.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure password history to remember 24 passwords.".to_string()),
        },

        // Audit and Logging
        ComplianceControl {
            id: "STIG-GEN-009".to_string(),
            control_id: "V-220714".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Audit logs must be retained for at least one year".to_string(),
            description: "Audit records provide a trace of user activities, enabling reconstruction of events for investigation.".to_string(),
            category: "Audit and Logging".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-11".to_string()],
            remediation_guidance: Some("Configure log retention policies to retain logs for minimum one year.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-010".to_string(),
            control_id: "V-220715".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Audit logs must be protected from unauthorized modification".to_string(),
            description: "Audit information includes all information needed to successfully audit system activity.".to_string(),
            category: "Audit and Logging".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-9".to_string()],
            remediation_guidance: Some("Configure file permissions to restrict audit log modification to authorized accounts only.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-011".to_string(),
            control_id: "V-220716".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Failed logon attempts must be audited".to_string(),
            description: "Auditing failed logon attempts provides visibility into potential brute force attacks.".to_string(),
            category: "Audit and Logging".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string()],
            remediation_guidance: Some("Enable auditing for failed logon events.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-012".to_string(),
            control_id: "V-220717".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Successful logon attempts must be audited".to_string(),
            description: "Auditing successful logons provides an audit trail for user access.".to_string(),
            category: "Audit and Logging".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-2".to_string()],
            remediation_guidance: Some("Enable auditing for successful logon events.".to_string()),
        },

        // Encryption
        ComplianceControl {
            id: "STIG-GEN-013".to_string(),
            control_id: "V-220718".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "FIPS 140-2 validated cryptographic modules must be used".to_string(),
            description: "FIPS 140-2 validation provides assurance that cryptographic modules meet security requirements.".to_string(),
            category: "Encryption".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Enable FIPS mode and ensure all cryptographic operations use FIPS-validated modules.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-014".to_string(),
            control_id: "V-220719".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Data at rest must be encrypted using AES 256 or equivalent".to_string(),
            description: "Encrypting data at rest protects against unauthorized access if storage media is compromised.".to_string(),
            category: "Encryption".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Enable full disk encryption using AES-256 or stronger algorithms.".to_string()),
        },
        ComplianceControl {
            id: "STIG-GEN-015".to_string(),
            control_id: "V-220720".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "TLS 1.2 or higher must be used for data in transit".to_string(),
            description: "TLS provides encryption for data transmitted over networks, protecting against interception.".to_string(),
            category: "Encryption".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Configure systems to require TLS 1.2 or higher. Disable SSLv3, TLS 1.0, and TLS 1.1.".to_string()),
        },
    ]
}

/// Windows-specific STIG controls
fn get_windows_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-WIN-001".to_string(),
            control_id: "V-220697".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Windows Defender Credential Guard must be running".to_string(),
            description: "Credential Guard uses virtualization-based security to protect credentials from theft.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-3".to_string()],
            remediation_guidance: Some("Enable Credential Guard via Group Policy or registry settings on compatible hardware.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-002".to_string(),
            control_id: "V-220698".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "BitLocker must be enabled on all fixed drives".to_string(),
            description: "BitLocker provides encryption for data at rest, protecting against unauthorized physical access.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Enable BitLocker on all fixed data drives with AES-256 encryption.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-003".to_string(),
            control_id: "V-220699".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Windows Firewall must be enabled on all network profiles".to_string(),
            description: "Windows Firewall provides host-based network filtering to block unauthorized connections.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable Windows Firewall for Domain, Private, and Public profiles.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-004".to_string(),
            control_id: "V-220700".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "SMBv1 must be disabled".to_string(),
            description: "SMBv1 has known vulnerabilities and should not be used. Modern systems should use SMBv3.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Disable SMBv1 client and server via PowerShell or Group Policy.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-005".to_string(),
            control_id: "V-220701".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "PowerShell script block logging must be enabled".to_string(),
            description: "Script block logging provides visibility into PowerShell script execution for security monitoring.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable PowerShell script block logging via Group Policy.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-006".to_string(),
            control_id: "V-220702".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "NTLM must be restricted to NTLMv2 only".to_string(),
            description: "NTLMv1 and LM authentication are vulnerable to relay and cracking attacks.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Configure 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM'.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-007".to_string(),
            control_id: "V-220703".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Anonymous SID/Name translation must be disabled".to_string(),
            description: "Anonymous SID translation can be used for reconnaissance to enumerate domain users.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Disable 'Network access: Allow anonymous SID/Name translation'.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-008".to_string(),
            control_id: "V-220704".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Remote Desktop Services must require Network Level Authentication".to_string(),
            description: "NLA provides additional authentication before establishing a full RDP connection.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Enable 'Require user authentication for remote connections by using Network Level Authentication'.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-009".to_string(),
            control_id: "V-220705".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Windows Defender Antivirus must be enabled and updated".to_string(),
            description: "Antivirus software provides protection against known malware threats.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string()],
            remediation_guidance: Some("Enable Windows Defender and ensure definitions are updated within the last 7 days.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-010".to_string(),
            control_id: "V-220721".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Local Administrator accounts must be renamed".to_string(),
            description: "Renaming default administrator accounts makes them harder to target in attacks.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Rename the built-in Administrator account to a non-standard name.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-011".to_string(),
            control_id: "V-220722".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Guest account must be disabled".to_string(),
            description: "The Guest account provides anonymous access and must be disabled.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Disable the Guest account via Local Security Policy or Group Policy.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WIN-012".to_string(),
            control_id: "V-220723".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "AutoPlay must be disabled for all drives".to_string(),
            description: "AutoPlay can execute malicious code from removable media without user interaction.".to_string(),
            category: "Windows Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Disable AutoPlay via Group Policy for all drive types.".to_string()),
        },
    ]
}

/// Linux-specific STIG controls
fn get_linux_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-LNX-001".to_string(),
            control_id: "V-230221".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "RHEL 8 must implement NIST FIPS-validated cryptography".to_string(),
            description: "FIPS mode ensures all cryptographic operations use validated algorithms.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Enable FIPS mode using fips-mode-setup --enable and reboot.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-002".to_string(),
            control_id: "V-230222".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "SSH must use FIPS-approved ciphers".to_string(),
            description: "Using FIPS-approved ciphers ensures encrypted SSH sessions meet DoD requirements.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-13".to_string()],
            remediation_guidance: Some("Configure /etc/crypto-policies/back-ends/openssh.config with FIPS-approved ciphers only.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-003".to_string(),
            control_id: "V-230223".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Root login via SSH must be disabled".to_string(),
            description: "Direct root login provides no accountability and should be disabled.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Set PermitRootLogin no in /etc/ssh/sshd_config.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-004".to_string(),
            control_id: "V-230224".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "AIDE must be configured to verify ACLs".to_string(),
            description: "AIDE provides integrity checking to detect unauthorized system modifications.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-7".to_string()],
            remediation_guidance: Some("Configure AIDE to include acl in the configuration and run aide --init.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-005".to_string(),
            control_id: "V-230225".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "SELinux must be enforcing".to_string(),
            description: "SELinux provides mandatory access control to limit the impact of compromised processes.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Set SELINUX=enforcing in /etc/selinux/config and reboot.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-006".to_string(),
            control_id: "V-230226".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Firewalld must be enabled".to_string(),
            description: "Host-based firewall provides network filtering at the system level.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable and start firewalld: systemctl enable --now firewalld.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-007".to_string(),
            control_id: "V-230227".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "USB storage must be disabled".to_string(),
            description: "Disabling USB storage prevents data exfiltration via removable media.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string()],
            remediation_guidance: Some("Add 'install usb-storage /bin/true' to /etc/modprobe.d/blacklist.conf.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-008".to_string(),
            control_id: "V-230228".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Audit system must audit sudo commands".to_string(),
            description: "Auditing sudo provides accountability for privileged actions.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Add audit rules for sudo execution to /etc/audit/rules.d/.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-009".to_string(),
            control_id: "V-230229".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "All world-writable directories must have sticky bit".to_string(),
            description: "Sticky bit prevents users from deleting files owned by others in shared directories.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Find and fix: find / -type d -perm -002 ! -perm -1000 -exec chmod +t {} \\;".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-010".to_string(),
            control_id: "V-230230".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Core dumps must be disabled".to_string(),
            description: "Core dumps may contain sensitive data and should be disabled.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-4".to_string()],
            remediation_guidance: Some("Set 'fs.suid_dumpable = 0' in /etc/sysctl.conf and add '* hard core 0' to /etc/security/limits.conf.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-011".to_string(),
            control_id: "V-230231".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "GRUB must require authentication".to_string(),
            description: "GRUB authentication prevents unauthorized boot parameter modifications.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Configure GRUB password using grub2-setpassword.".to_string()),
        },
        ComplianceControl {
            id: "STIG-LNX-012".to_string(),
            control_id: "V-230232".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "SSH idle timeout must be set to 10 minutes".to_string(),
            description: "Idle timeouts prevent abandoned sessions from being hijacked.".to_string(),
            category: "Linux Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-12".to_string()],
            remediation_guidance: Some("Set ClientAliveInterval 600 and ClientAliveCountMax 0 in sshd_config.".to_string()),
        },
    ]
}

/// Network device STIG controls
fn get_network_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-NET-001".to_string(),
            control_id: "V-220500".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Network devices must use SNMPv3 with authentication and privacy".to_string(),
            description: "SNMPv1/v2c transmit community strings in cleartext.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-3".to_string()],
            remediation_guidance: Some("Configure SNMPv3 with SHA authentication and AES-128 or higher encryption.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-002".to_string(),
            control_id: "V-220501".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Telnet must be disabled".to_string(),
            description: "Telnet transmits all data including credentials in cleartext.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Disable telnet service and use SSH for remote management.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-003".to_string(),
            control_id: "V-220502".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "HTTP management interface must be disabled".to_string(),
            description: "HTTP transmits credentials in cleartext. Use HTTPS instead.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Disable HTTP and enable HTTPS with TLS 1.2+ for web management.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-004".to_string(),
            control_id: "V-220503".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "SSH version 2 must be used".to_string(),
            description: "SSH version 1 has known vulnerabilities and should not be used.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Configure SSH to accept only version 2 connections.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-005".to_string(),
            control_id: "V-220504".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Unused ports must be administratively disabled".to_string(),
            description: "Unused ports can be exploited for unauthorized network access.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Administratively shut down all unused switch/router ports.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-006".to_string(),
            control_id: "V-220505".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "802.1X port-based access control must be enabled".to_string(),
            description: "802.1X provides authentication before network access is granted.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-17".to_string()],
            remediation_guidance: Some("Enable 802.1X authentication on all access ports.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-007".to_string(),
            control_id: "V-220506".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "BPDU Guard must be enabled on access ports".to_string(),
            description: "BPDU Guard prevents rogue switch attacks on access ports.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable BPDU Guard on all access layer switch ports.".to_string()),
        },
        ComplianceControl {
            id: "STIG-NET-008".to_string(),
            control_id: "V-220507".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Console and AUX ports must have timeouts configured".to_string(),
            description: "Console timeouts prevent unauthorized access via abandoned sessions.".to_string(),
            category: "Network Devices".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-12".to_string()],
            remediation_guidance: Some("Configure exec-timeout on console and aux lines to 10 minutes or less.".to_string()),
        },
    ]
}

/// Web server STIG controls
fn get_web_server_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-WEB-001".to_string(),
            control_id: "V-220800".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "TLS 1.2 or higher must be enforced".to_string(),
            description: "Older TLS/SSL versions have known vulnerabilities.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Configure web server to only accept TLS 1.2 and TLS 1.3 connections.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-002".to_string(),
            control_id: "V-220801".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "HSTS header must be configured".to_string(),
            description: "HSTS ensures browsers only connect via HTTPS.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Add Strict-Transport-Security header with max-age of at least 31536000.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-003".to_string(),
            control_id: "V-220802".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Server version headers must be removed".to_string(),
            description: "Version disclosure aids attackers in identifying vulnerabilities.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Configure server to suppress version information in Server header.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-004".to_string(),
            control_id: "V-220803".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Directory listing must be disabled".to_string(),
            description: "Directory listing exposes file structure and potentially sensitive files.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Disable directory browsing/autoindex in web server configuration.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-005".to_string(),
            control_id: "V-220804".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "X-Content-Type-Options header must be set".to_string(),
            description: "Prevents MIME type sniffing attacks.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Add X-Content-Type-Options: nosniff header.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-006".to_string(),
            control_id: "V-220805".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "X-Frame-Options header must be set".to_string(),
            description: "Prevents clickjacking attacks by controlling iframe embedding.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Add X-Frame-Options: DENY or SAMEORIGIN header.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-007".to_string(),
            control_id: "V-220806".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Content-Security-Policy header must be configured".to_string(),
            description: "CSP helps prevent XSS and other injection attacks.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Configure appropriate Content-Security-Policy header for the application.".to_string()),
        },
        ComplianceControl {
            id: "STIG-WEB-008".to_string(),
            control_id: "V-220807".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Web server must run as non-privileged user".to_string(),
            description: "Running as non-root limits the impact of a compromised web server.".to_string(),
            category: "Web Server".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Configure web server to run as a dedicated non-root service account.".to_string()),
        },
    ]
}

/// Database STIG controls
fn get_database_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-DB-001".to_string(),
            control_id: "V-220900".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Database connections must use TLS encryption".to_string(),
            description: "Database connections may contain sensitive data and credentials.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Enable TLS/SSL for all database connections and require encrypted connections.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-002".to_string(),
            control_id: "V-220901".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Default database accounts must be disabled or removed".to_string(),
            description: "Default accounts with known passwords are common attack vectors.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Disable or remove default accounts like 'sa', 'scott', 'system'.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-003".to_string(),
            control_id: "V-220902".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Database audit logging must be enabled".to_string(),
            description: "Audit logging provides accountability for database actions.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable database auditing for login attempts, privilege changes, and DDL operations.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-004".to_string(),
            control_id: "V-220903".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Database must not listen on all interfaces".to_string(),
            description: "Limiting listener interfaces reduces the attack surface.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Configure database to listen only on required interfaces.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-005".to_string(),
            control_id: "V-220904".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Sample databases must be removed".to_string(),
            description: "Sample databases may contain vulnerabilities and unnecessary exposure.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Remove sample databases like 'AdventureWorks', 'Northwind', 'scott'.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-006".to_string(),
            control_id: "V-220905".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Transparent Data Encryption must be enabled for sensitive data".to_string(),
            description: "TDE protects data at rest on the storage layer.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Enable TDE for databases containing sensitive or classified data.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-007".to_string(),
            control_id: "V-220906".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Database backup encryption must be enabled".to_string(),
            description: "Encrypted backups protect data if backup media is compromised.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-28".to_string()],
            remediation_guidance: Some("Enable encryption for all database backups using AES-256.".to_string()),
        },
        ComplianceControl {
            id: "STIG-DB-008".to_string(),
            control_id: "V-220907".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Database must enforce password complexity".to_string(),
            description: "Weak database passwords can be easily compromised.".to_string(),
            category: "Database".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Enable password policy enforcement for database authentication.".to_string()),
        },
    ]
}

/// Application security STIG controls
fn get_application_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-APP-001".to_string(),
            control_id: "V-221000".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Application must not store credentials in source code".to_string(),
            description: "Hardcoded credentials can be extracted from application binaries.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-5".to_string()],
            remediation_guidance: Some("Use secure credential storage mechanisms like vaults or environment variables.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-002".to_string(),
            control_id: "V-221001".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Input validation must be performed on all user input".to_string(),
            description: "Lack of input validation leads to injection attacks.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Implement whitelist-based input validation for all user-controllable data.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-003".to_string(),
            control_id: "V-221002".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Output encoding must be applied to prevent XSS".to_string(),
            description: "Unencoded output allows cross-site scripting attacks.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-10".to_string()],
            remediation_guidance: Some("Apply context-appropriate output encoding for all dynamic content.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-004".to_string(),
            control_id: "V-221003".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Session cookies must have Secure flag".to_string(),
            description: "Secure flag ensures cookies are only sent over HTTPS.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Set Secure flag on all session and authentication cookies.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-005".to_string(),
            control_id: "V-221004".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Session cookies must have HttpOnly flag".to_string(),
            description: "HttpOnly flag prevents JavaScript access to cookies.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-23".to_string()],
            remediation_guidance: Some("Set HttpOnly flag on all session cookies.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-006".to_string(),
            control_id: "V-221005".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Application must implement CSRF protection".to_string(),
            description: "CSRF allows attackers to perform actions on behalf of authenticated users.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-23".to_string()],
            remediation_guidance: Some("Implement anti-CSRF tokens for all state-changing operations.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-007".to_string(),
            control_id: "V-221006".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Error messages must not reveal sensitive information".to_string(),
            description: "Verbose errors can reveal system details useful to attackers.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-11".to_string()],
            remediation_guidance: Some("Implement generic error pages for production and log detailed errors securely.".to_string()),
        },
        ComplianceControl {
            id: "STIG-APP-008".to_string(),
            control_id: "V-221007".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Debug mode must be disabled in production".to_string(),
            description: "Debug mode exposes sensitive information and functionality.".to_string(),
            category: "Application Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Ensure debug=false or equivalent in all production configurations.".to_string()),
        },
    ]
}

/// Virtualization STIG controls
fn get_virtualization_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-VIRT-001".to_string(),
            control_id: "V-221100".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Hypervisor must be patched to the latest security level".to_string(),
            description: "Hypervisor vulnerabilities can affect all hosted VMs.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string()],
            remediation_guidance: Some("Apply latest security patches to hypervisor within 30 days of release.".to_string()),
        },
        ComplianceControl {
            id: "STIG-VIRT-002".to_string(),
            control_id: "V-221101".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "VM network isolation must be enforced".to_string(),
            description: "Network isolation prevents unauthorized VM-to-VM communication.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Configure virtual networks to enforce appropriate segmentation.".to_string()),
        },
        ComplianceControl {
            id: "STIG-VIRT-003".to_string(),
            control_id: "V-221102".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "vMotion traffic must be encrypted".to_string(),
            description: "vMotion moves VM memory contents which may contain sensitive data.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Enable vMotion encryption for all VM migrations.".to_string()),
        },
        ComplianceControl {
            id: "STIG-VIRT-004".to_string(),
            control_id: "V-221103".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "VM snapshots must not persist beyond 24 hours".to_string(),
            description: "Old snapshots consume resources and may contain outdated security configs.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-2".to_string()],
            remediation_guidance: Some("Implement automated cleanup of snapshots older than 24 hours.".to_string()),
        },
        ComplianceControl {
            id: "STIG-VIRT-005".to_string(),
            control_id: "V-221104".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Copy/paste between VMs and host must be disabled".to_string(),
            description: "Copy/paste can be used to exfiltrate data from isolated VMs.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string()],
            remediation_guidance: Some("Disable copy/paste operations in VM settings.".to_string()),
        },
        ComplianceControl {
            id: "STIG-VIRT-006".to_string(),
            control_id: "V-221105".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Unauthorized USB devices must not be connected to VMs".to_string(),
            description: "USB passthrough can be used to bypass network security controls.".to_string(),
            category: "Virtualization".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-MP-7".to_string()],
            remediation_guidance: Some("Disable or restrict USB passthrough for VMs.".to_string()),
        },
    ]
}

/// Cloud-specific STIG controls
fn get_cloud_controls() -> Vec<ComplianceControl> {
    vec![
        ComplianceControl {
            id: "STIG-CLOUD-001".to_string(),
            control_id: "V-221200".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Cloud root/admin accounts must use MFA".to_string(),
            description: "Root accounts have unrestricted access and require strong authentication.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-IA-2".to_string()],
            remediation_guidance: Some("Enable MFA for all root and administrative cloud accounts.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-002".to_string(),
            control_id: "V-221201".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Cloud storage must not be publicly accessible".to_string(),
            description: "Public storage buckets are a leading cause of data breaches.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Review and restrict public access on all cloud storage resources.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-003".to_string(),
            control_id: "V-221202".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Cloud logging must be enabled and centralized".to_string(),
            description: "Centralized logging enables security monitoring and incident response.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-6".to_string()],
            remediation_guidance: Some("Enable CloudTrail/Activity Log/Audit Logs and send to centralized SIEM.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-004".to_string(),
            control_id: "V-221203".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Cloud encryption keys must be customer-managed".to_string(),
            description: "Customer-managed keys provide control over data encryption.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SC-12".to_string()],
            remediation_guidance: Some("Use customer-managed encryption keys (CMK/CMEK) for sensitive data.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-005".to_string(),
            control_id: "V-221204".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Security groups must follow least privilege".to_string(),
            description: "Overly permissive security groups expand the attack surface.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Review and restrict security group rules to minimum required access.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-006".to_string(),
            control_id: "V-221205".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Flow logs must be enabled for all VPCs/VNets".to_string(),
            description: "Flow logs provide visibility into network traffic for security analysis.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable VPC Flow Logs, NSG Flow Logs, or equivalent for all networks.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-007".to_string(),
            control_id: "V-221206".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "Cloud resources must be deployed in approved regions".to_string(),
            description: "Data sovereignty requirements may restrict resource locations.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-4".to_string()],
            remediation_guidance: Some("Use service control policies to restrict deployments to approved regions.".to_string()),
        },
        ComplianceControl {
            id: "STIG-CLOUD-008".to_string(),
            control_id: "V-221207".to_string(),
            framework: ComplianceFramework::DodStig,
            title: "IAM policies must not use wildcard permissions".to_string(),
            description: "Wildcard permissions grant excessive access violating least privilege.".to_string(),
            category: "Cloud Security".to_string(),
            priority: ControlPriority::Critical,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-6".to_string()],
            remediation_guidance: Some("Review IAM policies and replace wildcards with specific resource ARNs.".to_string()),
        },
    ]
}

/// Get controls by STIG category
pub fn get_controls_by_category(category: &str) -> Vec<ComplianceControl> {
    get_controls()
        .into_iter()
        .filter(|c| c.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get all STIG categories
pub fn get_categories() -> Vec<&'static str> {
    vec![
        "Account Management",
        "Audit and Logging",
        "Encryption",
        "Windows Security",
        "Linux Security",
        "Network Devices",
        "Web Server",
        "Database",
        "Application Security",
        "Virtualization",
        "Cloud Security",
    ]
}

/// Map vulnerability to relevant STIG controls
pub fn map_vulnerability_to_controls(vuln_title: &str, vuln_description: &str) -> Vec<String> {
    let combined = format!("{} {}", vuln_title, vuln_description).to_lowercase();
    let mut matched_controls = Vec::new();

    // Password-related
    if combined.contains("password") || combined.contains("credential") || combined.contains("authentication") {
        matched_controls.extend(vec![
            "V-220707", "V-220708", "V-220709", "V-220710", "V-220711", "V-220712", "V-220713",
        ]);
    }

    // Encryption
    if combined.contains("encrypt") || combined.contains("tls") || combined.contains("ssl") || combined.contains("fips") {
        matched_controls.extend(vec!["V-220718", "V-220719", "V-220720", "V-220800"]);
    }

    // SMB
    if combined.contains("smb") || combined.contains("samba") {
        matched_controls.push("V-220700");
    }

    // SSH
    if combined.contains("ssh") {
        matched_controls.extend(vec!["V-230222", "V-230223", "V-230232", "V-220504"]);
    }

    // Audit/Logging
    if combined.contains("audit") || combined.contains("log") {
        matched_controls.extend(vec!["V-220714", "V-220715", "V-220716", "V-220717"]);
    }

    // XSS/Injection
    if combined.contains("xss") || combined.contains("injection") || combined.contains("script") {
        matched_controls.extend(vec!["V-221001", "V-221002", "V-221003"]);
    }

    // Headers
    if combined.contains("header") || combined.contains("hsts") || combined.contains("csp") {
        matched_controls.extend(vec!["V-220801", "V-220802", "V-220804", "V-220805", "V-220806"]);
    }

    // Cloud
    if combined.contains("s3") || combined.contains("bucket") || combined.contains("blob") || combined.contains("storage") {
        matched_controls.extend(vec!["V-221201", "V-221204"]);
    }

    matched_controls.sort();
    matched_controls.dedup();
    matched_controls.into_iter().map(String::from).collect()
}

use crate::types::Severity;

/// Map a vulnerability to relevant DoD STIG controls (with severity)
/// Used by the compliance control mapping system
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    _port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Password and credential vulnerabilities - CAT I
    if title_lower.contains("password") || title_lower.contains("credential") || title_lower.contains("authentication") {
        mappings.push(("V-220707".to_string(), Severity::Critical));
        mappings.push(("V-220708".to_string(), Severity::Critical));
        mappings.push(("V-220709".to_string(), Severity::High));
    }

    // Encryption and TLS vulnerabilities - CAT I/II
    if title_lower.contains("encrypt") || title_lower.contains("tls") || title_lower.contains("ssl")
        || title_lower.contains("fips") || title_lower.contains("plaintext") || title_lower.contains("unencrypted") {
        mappings.push(("V-220718".to_string(), Severity::Critical));
        mappings.push(("V-220719".to_string(), Severity::High));
        mappings.push(("V-220720".to_string(), Severity::High));
    }

    // SMB vulnerabilities - CAT II
    if title_lower.contains("smb") || title_lower.contains("samba") {
        mappings.push(("V-220700".to_string(), Severity::High));
    }

    // SSH vulnerabilities - CAT I/II
    if title_lower.contains("ssh") {
        mappings.push(("V-230222".to_string(), Severity::High));
        mappings.push(("V-230223".to_string(), Severity::High));
        mappings.push(("V-220504".to_string(), Severity::Medium));
    }

    // Audit and logging - CAT II/III
    if title_lower.contains("audit") || title_lower.contains("logging") || title_lower.contains("monitoring") {
        mappings.push(("V-220714".to_string(), Severity::Medium));
        mappings.push(("V-220715".to_string(), Severity::Medium));
    }

    // Web application security - XSS/Injection - CAT I
    if title_lower.contains("xss") || title_lower.contains("injection") || title_lower.contains("script")
        || title_lower.contains("sqli") || title_lower.contains("sql injection") {
        mappings.push(("V-221001".to_string(), Severity::Critical));
        mappings.push(("V-221002".to_string(), Severity::Critical));
        mappings.push(("V-221003".to_string(), Severity::High));
    }

    // Security headers - CAT II
    if title_lower.contains("header") || title_lower.contains("hsts") || title_lower.contains("csp")
        || title_lower.contains("x-frame") || title_lower.contains("clickjack") {
        mappings.push(("V-220801".to_string(), Severity::Medium));
        mappings.push(("V-220802".to_string(), Severity::Medium));
        mappings.push(("V-220804".to_string(), Severity::Medium));
    }

    // Cloud security - CAT II
    if title_lower.contains("s3") || title_lower.contains("bucket") || title_lower.contains("blob")
        || title_lower.contains("storage") || title_lower.contains("aws") || title_lower.contains("azure") {
        mappings.push(("V-221201".to_string(), Severity::High));
        mappings.push(("V-221204".to_string(), Severity::High));
    }

    // Account lockout - CAT II
    if title_lower.contains("lockout") || title_lower.contains("brute") || title_lower.contains("rate limit") {
        mappings.push(("V-220710".to_string(), Severity::High));
    }

    // Privilege escalation - CAT I
    if title_lower.contains("privilege") || title_lower.contains("escalation") || title_lower.contains("sudo")
        || title_lower.contains("root") || title_lower.contains("admin") {
        mappings.push(("V-230231".to_string(), Severity::Critical));
        mappings.push(("V-220503".to_string(), Severity::Critical));
    }

    // Firewall and network security - CAT II
    if title_lower.contains("firewall") || title_lower.contains("network") || title_lower.contains("port")
        || title_lower.contains("open service") {
        mappings.push(("V-220401".to_string(), Severity::High));
        mappings.push(("V-220701".to_string(), Severity::Medium));
    }

    // Antivirus and malware - CAT II
    if title_lower.contains("antivirus") || title_lower.contains("malware") || title_lower.contains("virus") {
        mappings.push(("V-220702".to_string(), Severity::High));
    }

    // Session management - CAT II
    if title_lower.contains("session") || title_lower.contains("timeout") || title_lower.contains("cookie") {
        mappings.push(("V-220807".to_string(), Severity::Medium));
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
        }
    }

    #[test]
    fn test_categories() {
        let categories = get_categories();
        assert!(categories.len() >= 10);
        assert!(categories.contains(&"Windows Security"));
        assert!(categories.contains(&"Linux Security"));
        assert!(categories.contains(&"Cloud Security"));
    }

    #[test]
    fn test_vulnerability_mapping() {
        let controls = map_vulnerability_to_controls("Weak Password Policy", "The system allows short passwords");
        assert!(!controls.is_empty());
        assert!(controls.contains(&"V-220707".to_string()));
    }
}
