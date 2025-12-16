//! CIS Benchmarks Controls
//!
//! Center for Internet Security configuration benchmarks for system hardening.
//! This module contains controls based on CIS Critical Security Controls v8.

use super::super::types::{ComplianceControl, ComplianceFramework, ControlPriority};
use crate::types::Severity;

/// Total number of CIS controls in this module
pub const CONTROL_COUNT: usize = 56;

/// Get all CIS Benchmark controls
pub fn get_controls() -> Vec<ComplianceControl> {
    vec![
        // Control 1: Inventory and Control of Enterprise Assets
        ComplianceControl {
            id: "CIS-1.1".to_string(),
            control_id: "1.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain Detailed Enterprise Asset Inventory".to_string(),
            description: "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets with the potential to store or process data.".to_string(),
            category: "Inventory and Control of Enterprise Assets".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "PCI-DSS-2.4".to_string()],
            remediation_guidance: Some("Implement automated asset discovery tools and maintain a Configuration Management Database (CMDB).".to_string()),
        },
        ComplianceControl {
            id: "CIS-1.2".to_string(),
            control_id: "1.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Address Unauthorized Assets".to_string(),
            description: "Ensure that a process exists to address unauthorized assets on a weekly basis.".to_string(),
            category: "Inventory and Control of Enterprise Assets".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-1.1".to_string()),
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Implement automated alerts for new devices and establish a review process.".to_string()),
        },
        ComplianceControl {
            id: "CIS-1.3".to_string(),
            control_id: "1.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Utilize an Active Discovery Tool".to_string(),
            description: "Utilize an active discovery tool to identify assets connected to the enterprise's network.".to_string(),
            category: "Inventory and Control of Enterprise Assets".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-1.1".to_string()),
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Deploy network scanning tools that run on a regular schedule.".to_string()),
        },
        ComplianceControl {
            id: "CIS-1.4".to_string(),
            control_id: "1.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Use Dynamic Host Configuration Protocol (DHCP) Logging".to_string(),
            description: "Use DHCP logging on all DHCP servers or Internet Protocol (IP) address management tools.".to_string(),
            category: "Inventory and Control of Enterprise Assets".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-1.1".to_string()),
            cross_references: vec!["NIST-AU-12".to_string()],
            remediation_guidance: Some("Enable DHCP logging and ensure logs are sent to centralized log management.".to_string()),
        },
        ComplianceControl {
            id: "CIS-1.5".to_string(),
            control_id: "1.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Use a Passive Asset Discovery Tool".to_string(),
            description: "Use a passive discovery tool to identify assets connected to the enterprise's network.".to_string(),
            category: "Inventory and Control of Enterprise Assets".to_string(),
            priority: ControlPriority::Low,
            automated_check: true,
            parent_id: Some("CIS-1.1".to_string()),
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Deploy passive network monitoring to detect devices without active probing.".to_string()),
        },

        // Control 2: Inventory and Control of Software Assets
        ComplianceControl {
            id: "CIS-2.1".to_string(),
            control_id: "2.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Software Inventory".to_string(),
            description: "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets.".to_string(),
            category: "Inventory and Control of Software Assets".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-CM-8".to_string(), "PCI-DSS-2.4".to_string()],
            remediation_guidance: Some("Use software inventory tools to track all installed applications.".to_string()),
        },
        ComplianceControl {
            id: "CIS-2.2".to_string(),
            control_id: "2.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Ensure Authorized Software is Currently Supported".to_string(),
            description: "Ensure that only currently supported software is designated as authorized in the software inventory.".to_string(),
            category: "Inventory and Control of Software Assets".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-2.1".to_string()),
            cross_references: vec!["NIST-SA-22".to_string()],
            remediation_guidance: Some("Maintain a list of end-of-life software and plan for upgrades or replacements.".to_string()),
        },
        ComplianceControl {
            id: "CIS-2.3".to_string(),
            control_id: "2.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Address Unauthorized Software".to_string(),
            description: "Ensure that unauthorized software is either removed or the inventory is updated in a timely manner.".to_string(),
            category: "Inventory and Control of Software Assets".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-2.1".to_string()),
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Implement application whitelisting or regular software audits.".to_string()),
        },
        ComplianceControl {
            id: "CIS-2.4".to_string(),
            control_id: "2.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Utilize Automated Software Inventory Tools".to_string(),
            description: "Utilize automated software inventory tools throughout the enterprise.".to_string(),
            category: "Inventory and Control of Software Assets".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-2.1".to_string()),
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Deploy endpoint management tools with software inventory capabilities.".to_string()),
        },
        ComplianceControl {
            id: "CIS-2.5".to_string(),
            control_id: "2.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Allowlist Authorized Software".to_string(),
            description: "Use technical controls to ensure that only authorized software can execute on enterprise assets.".to_string(),
            category: "Inventory and Control of Software Assets".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-2.1".to_string()),
            cross_references: vec!["NIST-CM-7".to_string()],
            remediation_guidance: Some("Implement application control policies using Windows AppLocker or similar tools.".to_string()),
        },

        // Control 3: Data Protection
        ComplianceControl {
            id: "CIS-3.1".to_string(),
            control_id: "3.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Data Management Process".to_string(),
            description: "Establish and maintain a data management process including data sensitivity classification.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-2".to_string(), "PCI-DSS-3.1".to_string()],
            remediation_guidance: Some("Develop a data classification policy and implement data handling procedures.".to_string()),
        },
        ComplianceControl {
            id: "CIS-3.2".to_string(),
            control_id: "3.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Data Inventory".to_string(),
            description: "Establish and maintain a data inventory based on the enterprise's data management process.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-3.1".to_string()),
            cross_references: vec!["NIST-CM-8".to_string()],
            remediation_guidance: Some("Use data discovery tools to identify and classify sensitive data.".to_string()),
        },
        ComplianceControl {
            id: "CIS-3.3".to_string(),
            control_id: "3.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Configure Data Access Control Lists".to_string(),
            description: "Configure data access control lists based on a user's need to know.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-3.1".to_string()),
            cross_references: vec!["NIST-AC-3".to_string()],
            remediation_guidance: Some("Implement role-based access control (RBAC) for all data repositories.".to_string()),
        },
        ComplianceControl {
            id: "CIS-3.4".to_string(),
            control_id: "3.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Enforce Data Retention".to_string(),
            description: "Retain data according to the enterprise's data management process.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("CIS-3.1".to_string()),
            cross_references: vec!["NIST-SI-12".to_string()],
            remediation_guidance: Some("Implement automated data retention and deletion policies.".to_string()),
        },
        ComplianceControl {
            id: "CIS-3.5".to_string(),
            control_id: "3.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Securely Dispose of Data".to_string(),
            description: "Securely dispose of data as outlined in the enterprise's data management process.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("CIS-3.1".to_string()),
            cross_references: vec!["NIST-MP-6".to_string()],
            remediation_guidance: Some("Use secure deletion tools and maintain disposal records.".to_string()),
        },
        ComplianceControl {
            id: "CIS-3.6".to_string(),
            control_id: "3.6".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Encrypt Data on End-User Devices".to_string(),
            description: "Encrypt data on end-user devices containing sensitive data.".to_string(),
            category: "Data Protection".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-3.1".to_string()),
            cross_references: vec!["NIST-SC-28".to_string(), "PCI-DSS-3.4".to_string()],
            remediation_guidance: Some("Enable full-disk encryption using BitLocker, FileVault, or similar tools.".to_string()),
        },

        // Control 4: Secure Configuration of Enterprise Assets and Software
        ComplianceControl {
            id: "CIS-4.1".to_string(),
            control_id: "4.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Secure Configuration Process".to_string(),
            description: "Establish and maintain a secure configuration process for enterprise assets and software.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CM-1".to_string(), "PCI-DSS-2.2".to_string()],
            remediation_guidance: Some("Document secure configuration standards based on industry benchmarks.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.2".to_string(),
            control_id: "4.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Secure Configuration Process for Network Infrastructure".to_string(),
            description: "Establish and maintain a secure configuration process for network infrastructure.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-CM-6".to_string()],
            remediation_guidance: Some("Use configuration management tools to enforce network device hardening.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.3".to_string(),
            control_id: "4.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Configure Automatic Session Locking on Enterprise Assets".to_string(),
            description: "Configure automatic session locking on enterprise assets after a defined period of inactivity.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-AC-11".to_string()],
            remediation_guidance: Some("Configure screen lock timeout to 15 minutes or less via Group Policy.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.4".to_string(),
            control_id: "4.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Implement and Manage a Firewall on Servers".to_string(),
            description: "Implement and manage a firewall on servers where supported and applicable.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-SC-7".to_string(), "PCI-DSS-1.2".to_string()],
            remediation_guidance: Some("Enable host-based firewalls with deny-by-default policies.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.5".to_string(),
            control_id: "4.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Implement and Manage a Firewall on End-User Devices".to_string(),
            description: "Implement and manage a host-based firewall or port-filtering tool on end-user devices.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Enable Windows Firewall or equivalent on all endpoints.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.6".to_string(),
            control_id: "4.6".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Securely Manage Enterprise Assets and Software".to_string(),
            description: "Securely manage enterprise assets and software using secure network protocols.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-SC-8".to_string()],
            remediation_guidance: Some("Use SSH, HTTPS, and encrypted protocols for all management access.".to_string()),
        },
        ComplianceControl {
            id: "CIS-4.7".to_string(),
            control_id: "4.7".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Manage Default Accounts on Enterprise Assets and Software".to_string(),
            description: "Manage default accounts on enterprise assets and software including disabling or removing them.".to_string(),
            category: "Secure Configuration".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-4.1".to_string()),
            cross_references: vec!["NIST-CM-6".to_string(), "PCI-DSS-2.1".to_string()],
            remediation_guidance: Some("Disable or rename default accounts and change default passwords.".to_string()),
        },

        // Control 5: Account Management
        ComplianceControl {
            id: "CIS-5.1".to_string(),
            control_id: "5.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain an Inventory of Accounts".to_string(),
            description: "Establish and maintain an inventory of all accounts managed in the enterprise.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-AC-2".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Implement centralized identity management and regular account reviews.".to_string()),
        },
        ComplianceControl {
            id: "CIS-5.2".to_string(),
            control_id: "5.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Use Unique Passwords".to_string(),
            description: "Use unique passwords for all enterprise assets where technically feasible.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-5.1".to_string()),
            cross_references: vec!["NIST-IA-5".to_string(), "PCI-DSS-8.2".to_string()],
            remediation_guidance: Some("Implement password policies requiring unique, complex passwords.".to_string()),
        },
        ComplianceControl {
            id: "CIS-5.3".to_string(),
            control_id: "5.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Disable Dormant Accounts".to_string(),
            description: "Delete or disable any dormant accounts after a period of 45 days of inactivity.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-5.1".to_string()),
            cross_references: vec!["NIST-AC-2".to_string()],
            remediation_guidance: Some("Implement automated account cleanup for inactive accounts.".to_string()),
        },
        ComplianceControl {
            id: "CIS-5.4".to_string(),
            control_id: "5.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Restrict Administrator Privileges to Dedicated Administrator Accounts".to_string(),
            description: "Restrict administrator privileges to dedicated administrator accounts on enterprise assets.".to_string(),
            category: "Account Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-5.1".to_string()),
            cross_references: vec!["NIST-AC-6".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Implement privileged access management and separate admin accounts.".to_string()),
        },

        // Control 6: Access Control Management
        ComplianceControl {
            id: "CIS-6.1".to_string(),
            control_id: "6.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish an Access Granting Process".to_string(),
            description: "Establish and follow a process for granting access to enterprise assets and software.".to_string(),
            category: "Access Control Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AC-1".to_string(), "PCI-DSS-7.1".to_string()],
            remediation_guidance: Some("Document and implement formal access request and approval workflows.".to_string()),
        },
        ComplianceControl {
            id: "CIS-6.2".to_string(),
            control_id: "6.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish an Access Revoking Process".to_string(),
            description: "Establish and follow a process for revoking access to enterprise assets and software.".to_string(),
            category: "Access Control Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("CIS-6.1".to_string()),
            cross_references: vec!["NIST-AC-2".to_string(), "PCI-DSS-8.1".to_string()],
            remediation_guidance: Some("Implement automated deprovisioning integrated with HR systems.".to_string()),
        },
        ComplianceControl {
            id: "CIS-6.3".to_string(),
            control_id: "6.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Require MFA for Externally-Exposed Applications".to_string(),
            description: "Require all externally-exposed enterprise or third-party applications to enforce MFA.".to_string(),
            category: "Access Control Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-6.1".to_string()),
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Implement multi-factor authentication for all external-facing applications.".to_string()),
        },
        ComplianceControl {
            id: "CIS-6.4".to_string(),
            control_id: "6.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Require MFA for Remote Network Access".to_string(),
            description: "Require MFA for remote network access including VPN connections.".to_string(),
            category: "Access Control Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-6.1".to_string()),
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Configure MFA for all VPN and remote access solutions.".to_string()),
        },
        ComplianceControl {
            id: "CIS-6.5".to_string(),
            control_id: "6.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Require MFA for Administrative Access".to_string(),
            description: "Require MFA for all administrative access accounts where supported.".to_string(),
            category: "Access Control Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-6.1".to_string()),
            cross_references: vec!["NIST-IA-2".to_string(), "PCI-DSS-8.3".to_string()],
            remediation_guidance: Some("Enable MFA for all privileged and administrative accounts.".to_string()),
        },

        // Control 7: Continuous Vulnerability Management
        ComplianceControl {
            id: "CIS-7.1".to_string(),
            control_id: "7.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Vulnerability Management Process".to_string(),
            description: "Establish and maintain a documented vulnerability management process for enterprise assets.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-RA-3".to_string(), "PCI-DSS-6.1".to_string()],
            remediation_guidance: Some("Document vulnerability management procedures including scanning, prioritization, and remediation.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.2".to_string(),
            control_id: "7.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Remediation Process".to_string(),
            description: "Establish and maintain a risk-based remediation strategy for addressing vulnerabilities.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Define SLAs for vulnerability remediation based on severity.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.3".to_string(),
            control_id: "7.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Perform Automated Operating System Patch Management".to_string(),
            description: "Perform automated operating system patch management on enterprise assets.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Implement automated patch management solutions like WSUS or SCCM.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.4".to_string(),
            control_id: "7.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Perform Automated Application Patch Management".to_string(),
            description: "Perform automated application patch management on enterprise assets.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Use application-specific update mechanisms and third-party patching tools.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.5".to_string(),
            control_id: "7.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Perform Automated Vulnerability Scans of Internal Enterprise Assets".to_string(),
            description: "Perform automated vulnerability scans of internal enterprise assets on a quarterly basis.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-11.2".to_string()],
            remediation_guidance: Some("Deploy vulnerability scanning tools and schedule regular scans.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.6".to_string(),
            control_id: "7.6".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets".to_string(),
            description: "Perform automated vulnerability scans of externally-exposed enterprise assets.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-RA-5".to_string(), "PCI-DSS-11.2".to_string()],
            remediation_guidance: Some("Perform external vulnerability scans monthly or after significant changes.".to_string()),
        },
        ComplianceControl {
            id: "CIS-7.7".to_string(),
            control_id: "7.7".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Remediate Detected Vulnerabilities".to_string(),
            description: "Remediate detected vulnerabilities in software through processes and tooling on a monthly basis.".to_string(),
            category: "Continuous Vulnerability Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-7.1".to_string()),
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Track remediation progress and verify fixes through rescanning.".to_string()),
        },

        // Control 8: Audit Log Management
        ComplianceControl {
            id: "CIS-8.1".to_string(),
            control_id: "8.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain an Audit Log Management Process".to_string(),
            description: "Establish and maintain an audit log management process that defines logging requirements.".to_string(),
            category: "Audit Log Management".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-AU-1".to_string(), "PCI-DSS-10.1".to_string()],
            remediation_guidance: Some("Document logging requirements including what to log and retention periods.".to_string()),
        },
        ComplianceControl {
            id: "CIS-8.2".to_string(),
            control_id: "8.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Collect Audit Logs".to_string(),
            description: "Collect audit logs from enterprise assets that process or store sensitive data.".to_string(),
            category: "Audit Log Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-8.1".to_string()),
            cross_references: vec!["NIST-AU-2".to_string(), "PCI-DSS-10.2".to_string()],
            remediation_guidance: Some("Configure systems to generate security logs and forward to SIEM.".to_string()),
        },
        ComplianceControl {
            id: "CIS-8.3".to_string(),
            control_id: "8.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Ensure Adequate Audit Log Storage".to_string(),
            description: "Ensure that audit log storage supports the retention defined in the audit log management process.".to_string(),
            category: "Audit Log Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-8.1".to_string()),
            cross_references: vec!["NIST-AU-4".to_string(), "PCI-DSS-10.7".to_string()],
            remediation_guidance: Some("Monitor log storage capacity and implement log rotation policies.".to_string()),
        },
        ComplianceControl {
            id: "CIS-8.4".to_string(),
            control_id: "8.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Standardize Time Synchronization".to_string(),
            description: "Standardize time synchronization using NTP or equivalent on enterprise assets.".to_string(),
            category: "Audit Log Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-8.1".to_string()),
            cross_references: vec!["NIST-AU-8".to_string(), "PCI-DSS-10.4".to_string()],
            remediation_guidance: Some("Configure NTP synchronization to authoritative time sources.".to_string()),
        },
        ComplianceControl {
            id: "CIS-8.5".to_string(),
            control_id: "8.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Collect Detailed Audit Logs".to_string(),
            description: "Configure detailed audit logging for enterprise assets containing sensitive data.".to_string(),
            category: "Audit Log Management".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-8.1".to_string()),
            cross_references: vec!["NIST-AU-3".to_string(), "PCI-DSS-10.2".to_string()],
            remediation_guidance: Some("Enable verbose logging including command history, file access, and authentication events.".to_string()),
        },

        // Control 9: Email and Web Browser Protections
        ComplianceControl {
            id: "CIS-9.1".to_string(),
            control_id: "9.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Ensure Use of Only Fully Supported Browsers and Email Clients".to_string(),
            description: "Ensure only fully supported browsers and email clients are allowed to execute in the enterprise.".to_string(),
            category: "Email and Web Browser Protections".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SA-22".to_string()],
            remediation_guidance: Some("Maintain approved browser list and remove unsupported versions.".to_string()),
        },
        ComplianceControl {
            id: "CIS-9.2".to_string(),
            control_id: "9.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Use DNS Filtering Services".to_string(),
            description: "Use DNS filtering services on all enterprise assets to block access to known malicious domains.".to_string(),
            category: "Email and Web Browser Protections".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-9.1".to_string()),
            cross_references: vec!["NIST-SC-7".to_string()],
            remediation_guidance: Some("Implement DNS filtering using services like Cisco Umbrella or Pi-hole.".to_string()),
        },

        // Control 10: Malware Defenses
        ComplianceControl {
            id: "CIS-10.1".to_string(),
            control_id: "10.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Deploy and Maintain Anti-Malware Software".to_string(),
            description: "Deploy and maintain anti-malware software on all enterprise assets.".to_string(),
            category: "Malware Defenses".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-3".to_string(), "PCI-DSS-5.1".to_string()],
            remediation_guidance: Some("Install endpoint protection on all systems and ensure definitions are current.".to_string()),
        },
        ComplianceControl {
            id: "CIS-10.2".to_string(),
            control_id: "10.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Configure Automatic Anti-Malware Signature Updates".to_string(),
            description: "Configure automatic updates for anti-malware signature files on all enterprise assets.".to_string(),
            category: "Malware Defenses".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-10.1".to_string()),
            cross_references: vec!["NIST-SI-3".to_string(), "PCI-DSS-5.2".to_string()],
            remediation_guidance: Some("Enable automatic signature updates with hourly or daily frequency.".to_string()),
        },
        ComplianceControl {
            id: "CIS-10.3".to_string(),
            control_id: "10.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Disable Autorun and Autoplay for Removable Media".to_string(),
            description: "Disable autorun and autoplay auto-execute functionality for removable media.".to_string(),
            category: "Malware Defenses".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-10.1".to_string()),
            cross_references: vec!["NIST-MP-7".to_string()],
            remediation_guidance: Some("Disable autorun via Group Policy on all Windows systems.".to_string()),
        },

        // Control 11: Data Recovery
        ComplianceControl {
            id: "CIS-11.1".to_string(),
            control_id: "11.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain a Data Recovery Process".to_string(),
            description: "Establish and maintain a data recovery process for in-scope enterprise assets.".to_string(),
            category: "Data Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: false,
            parent_id: None,
            cross_references: vec!["NIST-CP-9".to_string(), "PCI-DSS-9.5".to_string()],
            remediation_guidance: Some("Document backup procedures including frequency, retention, and testing.".to_string()),
        },
        ComplianceControl {
            id: "CIS-11.2".to_string(),
            control_id: "11.2".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Perform Automated Backups".to_string(),
            description: "Perform automated backups of in-scope enterprise assets weekly or more frequently.".to_string(),
            category: "Data Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-11.1".to_string()),
            cross_references: vec!["NIST-CP-9".to_string(), "PCI-DSS-9.5".to_string()],
            remediation_guidance: Some("Configure automated backup schedules and monitor backup completion.".to_string()),
        },
        ComplianceControl {
            id: "CIS-11.3".to_string(),
            control_id: "11.3".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Protect Recovery Data".to_string(),
            description: "Protect recovery data with equivalent controls to the original data.".to_string(),
            category: "Data Recovery".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: Some("CIS-11.1".to_string()),
            cross_references: vec!["NIST-CP-9".to_string()],
            remediation_guidance: Some("Encrypt backups and store in secure, access-controlled locations.".to_string()),
        },
        ComplianceControl {
            id: "CIS-11.4".to_string(),
            control_id: "11.4".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Establish and Maintain an Isolated Instance of Recovery Data".to_string(),
            description: "Establish and maintain an isolated instance of recovery data using versioning or air-gapping.".to_string(),
            category: "Data Recovery".to_string(),
            priority: ControlPriority::Medium,
            automated_check: true,
            parent_id: Some("CIS-11.1".to_string()),
            cross_references: vec!["NIST-CP-9".to_string()],
            remediation_guidance: Some("Implement offline or air-gapped backup copies for ransomware protection.".to_string()),
        },
        ComplianceControl {
            id: "CIS-11.5".to_string(),
            control_id: "11.5".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Test Data Recovery".to_string(),
            description: "Test backup recovery quarterly or more frequently for a sampling of enterprise assets.".to_string(),
            category: "Data Recovery".to_string(),
            priority: ControlPriority::Medium,
            automated_check: false,
            parent_id: Some("CIS-11.1".to_string()),
            cross_references: vec!["NIST-CP-4".to_string()],
            remediation_guidance: Some("Schedule and document regular restore tests to verify backup integrity.".to_string()),
        },

        // Control 12: Network Infrastructure Management
        ComplianceControl {
            id: "CIS-12.1".to_string(),
            control_id: "12.1".to_string(),
            framework: ComplianceFramework::CisBenchmarks,
            title: "Ensure Network Infrastructure is Up-to-Date".to_string(),
            description: "Ensure network infrastructure is kept up-to-date with security patches and vendor support.".to_string(),
            category: "Network Infrastructure Management".to_string(),
            priority: ControlPriority::High,
            automated_check: true,
            parent_id: None,
            cross_references: vec!["NIST-SI-2".to_string(), "PCI-DSS-6.2".to_string()],
            remediation_guidance: Some("Maintain firmware update schedules for all network devices.".to_string()),
        },
    ]
}

/// Map a vulnerability to relevant CIS controls
pub fn map_vulnerability(
    vuln_title: &str,
    _cve_id: Option<&str>,
    port: Option<u16>,
    _service: Option<&str>,
) -> Vec<(String, Severity)> {
    let mut mappings = Vec::new();
    let title_lower = vuln_title.to_lowercase();

    // Outdated software vulnerabilities
    if title_lower.contains("outdated")
        || title_lower.contains("end of life")
        || title_lower.contains("unsupported")
    {
        mappings.push(("CIS-2.2".to_string(), Severity::High));
        mappings.push(("CIS-7.3".to_string(), Severity::High));
        mappings.push(("CIS-7.4".to_string(), Severity::High));
    }

    // Default credentials
    if title_lower.contains("default password")
        || title_lower.contains("default credentials")
        || title_lower.contains("factory default")
    {
        mappings.push(("CIS-4.7".to_string(), Severity::Critical));
        mappings.push(("CIS-5.2".to_string(), Severity::High));
    }

    // Missing encryption
    if title_lower.contains("unencrypted")
        || title_lower.contains("plaintext")
        || title_lower.contains("cleartext")
    {
        mappings.push(("CIS-3.6".to_string(), Severity::High));
        mappings.push(("CIS-4.6".to_string(), Severity::High));
    }

    // Authentication issues
    if title_lower.contains("authentication bypass")
        || title_lower.contains("missing authentication")
    {
        mappings.push(("CIS-6.3".to_string(), Severity::Critical));
        mappings.push(("CIS-6.4".to_string(), Severity::Critical));
        mappings.push(("CIS-6.5".to_string(), Severity::Critical));
    }

    // Missing MFA
    if title_lower.contains("no mfa")
        || title_lower.contains("without multi-factor")
        || title_lower.contains("single factor")
    {
        mappings.push(("CIS-6.3".to_string(), Severity::High));
        mappings.push(("CIS-6.4".to_string(), Severity::High));
        mappings.push(("CIS-6.5".to_string(), Severity::High));
    }

    // Open ports / unnecessary services
    if title_lower.contains("unnecessary service")
        || title_lower.contains("open port")
        || title_lower.contains("exposed service")
    {
        mappings.push(("CIS-4.4".to_string(), Severity::Medium));
        mappings.push(("CIS-4.5".to_string(), Severity::Medium));
    }

    // Missing anti-malware
    if title_lower.contains("no antivirus")
        || title_lower.contains("missing endpoint protection")
    {
        mappings.push(("CIS-10.1".to_string(), Severity::High));
        mappings.push(("CIS-10.2".to_string(), Severity::Medium));
    }

    // Logging issues
    if title_lower.contains("logging disabled")
        || title_lower.contains("no audit")
        || title_lower.contains("missing logs")
    {
        mappings.push(("CIS-8.1".to_string(), Severity::Medium));
        mappings.push(("CIS-8.2".to_string(), Severity::Medium));
    }

    // Telnet/insecure protocols
    if port == Some(23) || title_lower.contains("telnet") {
        mappings.push(("CIS-4.6".to_string(), Severity::High));
    }

    // FTP
    if port == Some(21) || title_lower.contains("ftp") && !title_lower.contains("sftp") {
        mappings.push(("CIS-4.6".to_string(), Severity::Medium));
    }

    mappings
}
