#![allow(dead_code)]
//! MITRE ATT&CK Technique Library
//!
//! This module provides a comprehensive library of MITRE ATT&CK techniques
//! that can be simulated for breach and attack simulation testing.

use super::types::{AttackTechnique, ExecutionMode, MitreTactic, PayloadType};
use std::collections::HashMap;

/// Library of attack techniques organized by MITRE ATT&CK framework
pub struct TechniqueLibrary {
    techniques: HashMap<String, AttackTechnique>,
}

impl TechniqueLibrary {
    /// Create a new technique library with all available techniques
    pub fn new() -> Self {
        let mut library = Self {
            techniques: HashMap::new(),
        };
        library.load_techniques();
        library
    }

    /// Get a technique by ID
    pub fn get(&self, technique_id: &str) -> Option<&AttackTechnique> {
        self.techniques.get(technique_id)
    }

    /// Get all techniques
    pub fn all_techniques(&self) -> Vec<&AttackTechnique> {
        self.techniques.values().collect()
    }

    /// Get techniques by tactic
    pub fn by_tactic(&self, tactic: MitreTactic) -> Vec<&AttackTechnique> {
        self.techniques
            .values()
            .filter(|t| t.tactics.contains(&tactic))
            .collect()
    }

    /// Get safe techniques only
    pub fn safe_techniques(&self) -> Vec<&AttackTechnique> {
        self.techniques.values().filter(|t| t.is_safe).collect()
    }

    /// Get techniques by platform
    pub fn by_platform(&self, platform: &str) -> Vec<&AttackTechnique> {
        let platform_lower = platform.to_lowercase();
        self.techniques
            .values()
            .filter(|t| {
                t.platforms
                    .iter()
                    .any(|p| p.to_lowercase() == platform_lower)
            })
            .collect()
    }

    /// Get techniques by payload type
    pub fn by_payload_type(&self, payload_type: PayloadType) -> Vec<&AttackTechnique> {
        self.techniques
            .values()
            .filter(|t| t.payload_types.contains(&payload_type))
            .collect()
    }

    /// Search techniques by name or description
    pub fn search(&self, query: &str) -> Vec<&AttackTechnique> {
        let query_lower = query.to_lowercase();
        self.techniques
            .values()
            .filter(|t| {
                t.name.to_lowercase().contains(&query_lower)
                    || t.description.to_lowercase().contains(&query_lower)
                    || t.technique_id.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Check if a technique exists
    pub fn exists(&self, technique_id: &str) -> bool {
        self.techniques.contains_key(technique_id)
    }

    /// Get count of techniques
    pub fn count(&self) -> usize {
        self.techniques.len()
    }

    /// Load all techniques into the library
    fn load_techniques(&mut self) {
        self.load_initial_access_techniques();
        self.load_execution_techniques();
        self.load_persistence_techniques();
        self.load_privilege_escalation_techniques();
        self.load_defense_evasion_techniques();
        self.load_credential_access_techniques();
        self.load_discovery_techniques();
        self.load_lateral_movement_techniques();
        self.load_collection_techniques();
        self.load_command_and_control_techniques();
        self.load_exfiltration_techniques();
        self.load_impact_techniques();
    }

    fn add(&mut self, technique: AttackTechnique) {
        self.techniques
            .insert(technique.technique_id.clone(), technique);
    }

    // ========================================================================
    // Initial Access (TA0001)
    // ========================================================================

    fn load_initial_access_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1190",
                "Exploit Public-Facing Application",
                "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                vec![MitreTactic::InitialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon])
            .with_detection_sources(vec!["Application Log".to_string(), "Network Traffic".to_string()])
            .with_risk_level(5)
            .with_min_mode(ExecutionMode::Simulation),
        );

        self.add(
            AttackTechnique::new(
                "T1566.001",
                "Spearphishing Attachment",
                "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
                vec![MitreTactic::InitialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["Email Gateway".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1566.002",
                "Spearphishing Link",
                "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.",
                vec![MitreTactic::InitialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon, PayloadType::DnsBeacon])
            .with_detection_sources(vec!["Email Gateway".to_string(), "Network Traffic".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1133",
                "External Remote Services",
                "Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
                vec![MitreTactic::InitialAccess, MitreTactic::Persistence],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Logon Session".to_string(), "Network Traffic".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1078",
                "Valid Accounts",
                "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                vec![MitreTactic::InitialAccess, MitreTactic::Persistence, MitreTactic::PrivilegeEscalation, MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::LogInjection])
            .with_detection_sources(vec!["Logon Session".to_string(), "User Account".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1195.002",
                "Compromise Software Supply Chain",
                "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.",
                vec![MitreTactic::InitialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Integrity Monitoring".to_string()])
            .with_risk_level(7)
            .with_min_mode(ExecutionMode::DryRun),
        );
    }

    // ========================================================================
    // Execution (TA0002)
    // ========================================================================

    fn load_execution_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1059.001",
                "PowerShell",
                "Adversaries may abuse PowerShell commands and scripts for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Script Execution".to_string(), "Process Creation".to_string(), "Module Load".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1059.003",
                "Windows Command Shell",
                "Adversaries may abuse the Windows command shell for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Command Execution".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1059.004",
                "Unix Shell",
                "Adversaries may abuse Unix shell commands and scripts for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Command Execution".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1059.005",
                "Visual Basic",
                "Adversaries may abuse Visual Basic (VB) for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Script Execution".to_string(), "Process Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1059.006",
                "Python",
                "Adversaries may abuse Python commands and scripts for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Script Execution".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1059.007",
                "JavaScript",
                "Adversaries may abuse various implementations of JavaScript for execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Script Execution".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1053.005",
                "Scheduled Task",
                "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.",
                vec![MitreTactic::Execution, MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::LogInjection])
            .with_detection_sources(vec!["Scheduled Job".to_string(), "Process Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1053.003",
                "Cron",
                "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code.",
                vec![MitreTactic::Execution, MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Scheduled Job".to_string(), "File Modification".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1204.001",
                "Malicious Link",
                "An adversary may rely upon a user clicking a malicious link in order to gain execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1204.002",
                "Malicious File",
                "An adversary may rely upon a user opening a malicious file in order to gain execution.",
                vec![MitreTactic::Execution],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Creation".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );
    }

    // ========================================================================
    // Persistence (TA0003)
    // ========================================================================

    fn load_persistence_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
                vec![MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::RegistryMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Windows Registry".to_string(), "File Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1543.002",
                "Systemd Service",
                "Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.",
                vec![MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["linux".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Service Creation".to_string(), "File Modification".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1543.003",
                "Windows Service",
                "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.",
                vec![MitreTactic::Persistence, MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::RegistryMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Service Creation".to_string(), "Windows Registry".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1098.004",
                "SSH Authorized Keys",
                "Adversaries may modify the SSH authorized_keys file to maintain persistence on a victim host.",
                vec![MitreTactic::Persistence],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Modification".to_string(), "Logon Session".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1136.001",
                "Local Account",
                "Adversaries may create a local account to maintain access to victim systems.",
                vec![MitreTactic::Persistence],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::LogInjection])
            .with_detection_sources(vec!["User Account".to_string(), "Process Creation".to_string()])
            .with_risk_level(6)
            .with_min_mode(ExecutionMode::DryRun),
        );
    }

    // ========================================================================
    // Privilege Escalation (TA0004)
    // ========================================================================

    fn load_privilege_escalation_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1548.002",
                "Bypass User Account Control",
                "Adversaries may bypass UAC mechanisms to elevate process privileges on system.",
                vec![MitreTactic::PrivilegeEscalation, MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::RegistryMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Windows Registry".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1548.001",
                "Setuid and Setgid",
                "Adversaries may perform shell escapes or exploit vulnerabilities in an application with the setsuid or setgid bits to get code running in a different user's context.",
                vec![MitreTactic::PrivilegeEscalation, MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["File Modification".to_string(), "Process Creation".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1068",
                "Exploitation for Privilege Escalation",
                "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
                vec![MitreTactic::PrivilegeEscalation],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Application Log".to_string()])
            .with_risk_level(7)
            .with_min_mode(ExecutionMode::DryRun),
        );

        self.add(
            AttackTechnique::new(
                "T1055",
                "Process Injection",
                "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
                vec![MitreTactic::PrivilegeEscalation, MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::MemoryMarker, PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Access".to_string(), "Process Modification".to_string()])
            .with_risk_level(7),
        );
    }

    // ========================================================================
    // Defense Evasion (TA0005)
    // ========================================================================

    fn load_defense_evasion_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1070.001",
                "Clear Windows Event Logs",
                "Adversaries may clear Windows Event Logs to hide the activity of an intrusion.",
                vec![MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::LogInjection])
            .with_detection_sources(vec!["Windows Event Log".to_string(), "Process Creation".to_string()])
            .with_risk_level(6)
            .with_min_mode(ExecutionMode::DryRun),
        );

        self.add(
            AttackTechnique::new(
                "T1070.003",
                "Clear Command History",
                "Adversaries may clear a command history log on a compromised system to hide actions taken by them.",
                vec![MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Modification".to_string(), "Command Execution".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1036.005",
                "Match Legitimate Name or Location",
                "Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them.",
                vec![MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Metadata".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1027",
                "Obfuscated Files or Information",
                "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
                vec![MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Metadata".to_string(), "Process Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1562.001",
                "Disable or Modify Tools",
                "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.",
                vec![MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Sensor Health".to_string(), "Process Termination".to_string()])
            .with_risk_level(7)
            .with_min_mode(ExecutionMode::DryRun),
        );
    }

    // ========================================================================
    // Credential Access (TA0006)
    // ========================================================================

    fn load_credential_access_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1003.001",
                "LSASS Memory",
                "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::MemoryMarker])
            .with_detection_sources(vec!["Process Access".to_string(), "OS Credential Dumping".to_string()])
            .with_risk_level(8)
            .with_min_mode(ExecutionMode::DryRun),
        );

        self.add(
            AttackTechnique::new(
                "T1003.003",
                "NTDS",
                "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information.",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Command Execution".to_string(), "File Access".to_string()])
            .with_risk_level(9)
            .with_min_mode(ExecutionMode::DryRun),
        );

        self.add(
            AttackTechnique::new(
                "T1110.001",
                "Password Guessing",
                "Adversaries may use password guessing to attempt to guess passwords of user accounts.",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::LogInjection])
            .with_detection_sources(vec!["User Account".to_string(), "Application Log".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1110.003",
                "Password Spraying",
                "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::LogInjection])
            .with_detection_sources(vec!["User Account".to_string(), "Application Log".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1558.003",
                "Kerberoasting",
                "Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket.",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::LogInjection])
            .with_detection_sources(vec!["Active Directory".to_string(), "Network Traffic".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1555.003",
                "Credentials from Web Browsers",
                "Adversaries may acquire credentials from web browsers by reading files specific to the target browser.",
                vec![MitreTactic::CredentialAccess],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Access".to_string(), "Process Access".to_string()])
            .with_risk_level(5),
        );
    }

    // ========================================================================
    // Discovery (TA0007)
    // ========================================================================

    fn load_discovery_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1082",
                "System Information Discovery",
                "An adversary may attempt to get detailed information about the operating system and hardware.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "OS API Execution".to_string()])
            .with_risk_level(2),
        );

        self.add(
            AttackTechnique::new(
                "T1083",
                "File and Directory Discovery",
                "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Command Execution".to_string()])
            .with_risk_level(2),
        );

        self.add(
            AttackTechnique::new(
                "T1087.001",
                "Local Account",
                "Adversaries may attempt to get a listing of local system accounts.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Command Execution".to_string()])
            .with_risk_level(3),
        );

        self.add(
            AttackTechnique::new(
                "T1087.002",
                "Domain Account",
                "Adversaries may attempt to get a listing of domain accounts.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Process Creation".to_string(), "Active Directory".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1016",
                "System Network Configuration Discovery",
                "Adversaries may look for details about the network configuration and settings.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string()])
            .with_risk_level(2),
        );

        self.add(
            AttackTechnique::new(
                "T1049",
                "System Network Connections Discovery",
                "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string()])
            .with_risk_level(2),
        );

        self.add(
            AttackTechnique::new(
                "T1057",
                "Process Discovery",
                "Adversaries may attempt to get information about running processes on a system.",
                vec![MitreTactic::Discovery],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string()])
            .with_risk_level(2),
        );
    }

    // ========================================================================
    // Lateral Movement (TA0008)
    // ========================================================================

    fn load_lateral_movement_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1021.001",
                "Remote Desktop Protocol",
                "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
                vec![MitreTactic::LateralMovement],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::LogInjection])
            .with_detection_sources(vec!["Logon Session".to_string(), "Network Traffic".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1021.002",
                "SMB/Windows Admin Shares",
                "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).",
                vec![MitreTactic::LateralMovement],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::FileMarker])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Share Access".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1021.004",
                "SSH",
                "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH).",
                vec![MitreTactic::LateralMovement],
            )
            .with_platforms(vec!["linux".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::LogInjection])
            .with_detection_sources(vec!["Logon Session".to_string(), "Process Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1570",
                "Lateral Tool Transfer",
                "Adversaries may transfer tools or other files between systems in a compromised environment.",
                vec![MitreTactic::LateralMovement],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker, PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "File Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1550.002",
                "Pass the Hash",
                "Adversaries may use stolen password hashes to move laterally within an environment.",
                vec![MitreTactic::LateralMovement, MitreTactic::DefenseEvasion],
            )
            .with_platforms(vec!["windows".to_string()])
            .with_payload_types(vec![PayloadType::LogInjection])
            .with_detection_sources(vec!["Logon Session".to_string(), "User Account".to_string()])
            .with_risk_level(7)
            .with_min_mode(ExecutionMode::DryRun),
        );
    }

    // ========================================================================
    // Collection (TA0009)
    // ========================================================================

    fn load_collection_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1005",
                "Data from Local System",
                "Adversaries may search local system sources to find files of interest and sensitive data prior to Exfiltration.",
                vec![MitreTactic::Collection],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["File Access".to_string(), "Command Execution".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1039",
                "Data from Network Shared Drive",
                "Adversaries may search network shares on computers they have compromised to find files of interest.",
                vec![MitreTactic::Collection],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::FileMarker])
            .with_detection_sources(vec!["Network Share Access".to_string(), "File Access".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1560.001",
                "Archive via Utility",
                "An adversary may compress and/or encrypt data that is collected prior to exfiltration using 3rd party utilities.",
                vec![MitreTactic::Collection],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "File Creation".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1113",
                "Screen Capture",
                "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.",
                vec![MitreTactic::Collection],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::FileMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "OS API Execution".to_string()])
            .with_risk_level(4),
        );
    }

    // ========================================================================
    // Command and Control (TA0011)
    // ========================================================================

    fn load_command_and_control_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1071.001",
                "Web Protocols",
                "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Traffic Content".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1071.004",
                "DNS",
                "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::DnsBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Traffic Content".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1105",
                "Ingress Tool Transfer",
                "Adversaries may transfer tools or other files from an external system into a compromised environment.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon, PayloadType::FileMarker])
            .with_detection_sources(vec!["Network Traffic".to_string(), "File Creation".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1571",
                "Non-Standard Port",
                "Adversaries may communicate using a protocol and port paring that are typically not associated.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Traffic Flow".to_string()])
            .with_risk_level(4),
        );

        self.add(
            AttackTechnique::new(
                "T1572",
                "Protocol Tunneling",
                "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon, PayloadType::DnsBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Traffic Content".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1573.001",
                "Symmetric Cryptography",
                "Adversaries may employ symmetric encryption algorithm to conceal command and control traffic.",
                vec![MitreTactic::CommandAndControl],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string()])
            .with_risk_level(5),
        );
    }

    // ========================================================================
    // Exfiltration (TA0010)
    // ========================================================================

    fn load_exfiltration_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1041",
                "Exfiltration Over C2 Channel",
                "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
                vec![MitreTactic::Exfiltration],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon, PayloadType::DnsBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Network Traffic Content".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1048.001",
                "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel.",
                vec![MitreTactic::Exfiltration],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::NetworkBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string()])
            .with_risk_level(6),
        );

        self.add(
            AttackTechnique::new(
                "T1567.002",
                "Exfiltration to Cloud Storage",
                "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel.",
                vec![MitreTactic::Exfiltration],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon])
            .with_detection_sources(vec!["Network Traffic".to_string(), "Cloud Storage".to_string()])
            .with_risk_level(5),
        );

        self.add(
            AttackTechnique::new(
                "T1537",
                "Transfer Data to Cloud Account",
                "Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control.",
                vec![MitreTactic::Exfiltration],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::HttpBeacon])
            .with_detection_sources(vec!["Cloud Storage".to_string(), "Network Traffic".to_string()])
            .with_risk_level(6),
        );
    }

    // ========================================================================
    // Impact (TA0040)
    // ========================================================================

    fn load_impact_techniques(&mut self) {
        self.add(
            AttackTechnique::new(
                "T1486",
                "Data Encrypted for Impact",
                "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
                vec![MitreTactic::Impact],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::FileMarker])
            .with_detection_sources(vec!["File Modification".to_string(), "Process Creation".to_string()])
            .with_risk_level(9)
            .with_min_mode(ExecutionMode::DryRun)
            .as_unsafe(),
        );

        self.add(
            AttackTechnique::new(
                "T1490",
                "Inhibit System Recovery",
                "Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system.",
                vec![MitreTactic::Impact],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Windows Registry".to_string()])
            .with_risk_level(8)
            .with_min_mode(ExecutionMode::DryRun)
            .as_unsafe(),
        );

        self.add(
            AttackTechnique::new(
                "T1489",
                "Service Stop",
                "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.",
                vec![MitreTactic::Impact],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker, PayloadType::LogInjection])
            .with_detection_sources(vec!["Service Modification".to_string(), "Process Termination".to_string()])
            .with_risk_level(6)
            .with_min_mode(ExecutionMode::DryRun),
        );

        self.add(
            AttackTechnique::new(
                "T1529",
                "System Shutdown/Reboot",
                "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.",
                vec![MitreTactic::Impact],
            )
            .with_platforms(vec!["linux".to_string(), "windows".to_string(), "macos".to_string()])
            .with_payload_types(vec![PayloadType::ProcessMarker])
            .with_detection_sources(vec!["Process Creation".to_string(), "Sensor Health".to_string()])
            .with_risk_level(7)
            .with_min_mode(ExecutionMode::DryRun)
            .as_unsafe(),
        );
    }
}

impl Default for TechniqueLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_creation() {
        let library = TechniqueLibrary::new();
        assert!(library.count() > 0);
    }

    #[test]
    fn test_get_technique() {
        let library = TechniqueLibrary::new();
        let technique = library.get("T1059.001");
        assert!(technique.is_some());
        assert_eq!(technique.unwrap().name, "PowerShell");
    }

    #[test]
    fn test_by_tactic() {
        let library = TechniqueLibrary::new();
        let execution_techniques = library.by_tactic(MitreTactic::Execution);
        assert!(!execution_techniques.is_empty());
    }

    #[test]
    fn test_safe_techniques() {
        let library = TechniqueLibrary::new();
        let safe = library.safe_techniques();
        assert!(!safe.is_empty());
        for t in safe {
            assert!(t.is_safe);
        }
    }

    #[test]
    fn test_search() {
        let library = TechniqueLibrary::new();
        let results = library.search("PowerShell");
        assert!(!results.is_empty());
    }
}
