//! MITRE ATT&CK mappings for HeroForge attack types

#![allow(dead_code)]

use super::types::{MitreTactic, MitreTechnique};
use std::collections::HashMap;

/// Maps HeroForge attack types to MITRE ATT&CK techniques
pub struct MitreMapper {
    techniques: HashMap<String, MitreTechnique>,
    attack_mappings: HashMap<String, Vec<String>>,  // attack_type -> technique_ids
}

impl MitreMapper {
    pub fn new() -> Self {
        let mut mapper = Self {
            techniques: HashMap::new(),
            attack_mappings: HashMap::new(),
        };
        mapper.initialize_techniques();
        mapper.initialize_mappings();
        mapper
    }

    /// Get technique by ID
    pub fn get_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Get all techniques for a tactic
    pub fn get_techniques_for_tactic(&self, tactic: &MitreTactic) -> Vec<&MitreTechnique> {
        self.techniques.values()
            .filter(|t| &t.tactic == tactic)
            .collect()
    }

    /// Get technique IDs for a HeroForge attack type
    pub fn get_techniques_for_attack(&self, attack_type: &str) -> Vec<String> {
        self.attack_mappings
            .get(attack_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Get attack types that can test a given technique (reverse lookup)
    pub fn get_attack_types_for_technique(&self, technique_id: &str) -> Option<Vec<&str>> {
        let mut attack_types = Vec::new();
        for (attack_type, technique_ids) in &self.attack_mappings {
            if technique_ids.iter().any(|id| id == technique_id || technique_id.starts_with(id)) {
                attack_types.push(attack_type.as_str());
            }
        }
        if attack_types.is_empty() {
            None
        } else {
            Some(attack_types)
        }
    }

    /// Get all techniques
    pub fn all_techniques(&self) -> Vec<&MitreTechnique> {
        self.techniques.values().collect()
    }

    /// Get all tactics with their techniques
    pub fn get_matrix(&self) -> HashMap<MitreTactic, Vec<&MitreTechnique>> {
        let mut matrix = HashMap::new();
        for tactic in MitreTactic::all() {
            let techniques = self.get_techniques_for_tactic(&tactic);
            matrix.insert(tactic, techniques);
        }
        matrix
    }

    fn initialize_techniques(&mut self) {
        // Credential Access
        self.add_technique(MitreTechnique {
            id: "T1110".to_string(),
            name: "Brute Force".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may use brute force techniques to gain access to accounts.".to_string(),
            data_sources: vec![
                "Application Log: Application Log Content".to_string(),
                "User Account: User Account Authentication".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1110.003".to_string(),
            name: "Password Spraying".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may use a single password against many accounts.".to_string(),
            data_sources: vec![
                "Application Log: Application Log Content".to_string(),
                "User Account: User Account Authentication".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1110".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1558".to_string(),
            name: "Steal or Forge Kerberos Tickets".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to subvert Kerberos authentication.".to_string(),
            data_sources: vec![
                "Active Directory: Active Directory Credential Request".to_string(),
                "Logon Session: Logon Session Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1558.003".to_string(),
            name: "Kerberoasting".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may abuse Kerberos to collect service tickets.".to_string(),
            data_sources: vec![
                "Active Directory: Active Directory Credential Request".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1558".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1558.004".to_string(),
            name: "AS-REP Roasting".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may reveal credentials of accounts without Kerberos preauthentication.".to_string(),
            data_sources: vec![
                "Active Directory: Active Directory Credential Request".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1558".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1003".to_string(),
            name: "OS Credential Dumping".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to dump credentials.".to_string(),
            data_sources: vec![
                "Command: Command Execution".to_string(),
                "Process: Process Access".to_string(),
                "File: File Access".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1003.001".to_string(),
            name: "LSASS Memory".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to access LSASS memory.".to_string(),
            data_sources: vec![
                "Process: Process Access".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1003".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1003.002".to_string(),
            name: "Security Account Manager".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to access the SAM database.".to_string(),
            data_sources: vec![
                "File: File Access".to_string(),
                "Command: Command Execution".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1003".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1003.003".to_string(),
            name: "NTDS".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to access NTDS.dit for credential dumping.".to_string(),
            data_sources: vec![
                "File: File Access".to_string(),
                "Command: Command Execution".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1003".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1003.006".to_string(),
            name: "DCSync".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may use DCSync to extract credentials from AD.".to_string(),
            data_sources: vec![
                "Active Directory: Active Directory Object Access".to_string(),
                "Network Traffic: Network Traffic Content".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1003".to_string()),
        });

        // Lateral Movement
        self.add_technique(MitreTechnique {
            id: "T1557".to_string(),
            name: "Adversary-in-the-Middle".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may attempt to position themselves in network traffic.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Content".to_string(),
                "Network Traffic: Network Traffic Flow".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1557.001".to_string(),
            name: "LLMNR/NBT-NS Poisoning and SMB Relay".to_string(),
            tactic: MitreTactic::CredentialAccess,
            description: "Adversaries may spoof LLMNR/NBT-NS responses and relay SMB.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Content".to_string(),
                "Network Traffic: Network Traffic Flow".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1557".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1550".to_string(),
            name: "Use Alternate Authentication Material".to_string(),
            tactic: MitreTactic::LateralMovement,
            description: "Adversaries may use alternate authentication material for lateral movement.".to_string(),
            data_sources: vec![
                "Logon Session: Logon Session Creation".to_string(),
                "User Account: User Account Authentication".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1550.002".to_string(),
            name: "Pass the Hash".to_string(),
            tactic: MitreTactic::LateralMovement,
            description: "Adversaries may use pass the hash for lateral movement.".to_string(),
            data_sources: vec![
                "Logon Session: Logon Session Creation".to_string(),
                "User Account: User Account Authentication".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1550".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1021".to_string(),
            name: "Remote Services".to_string(),
            tactic: MitreTactic::LateralMovement,
            description: "Adversaries may use remote services for lateral movement.".to_string(),
            data_sources: vec![
                "Logon Session: Logon Session Creation".to_string(),
                "Network Traffic: Network Connection Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1021.002".to_string(),
            name: "SMB/Windows Admin Shares".to_string(),
            tactic: MitreTactic::LateralMovement,
            description: "Adversaries may use SMB for lateral movement.".to_string(),
            data_sources: vec![
                "Logon Session: Logon Session Creation".to_string(),
                "Network Share: Network Share Access".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1021".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1021.006".to_string(),
            name: "Windows Remote Management".to_string(),
            tactic: MitreTactic::LateralMovement,
            description: "Adversaries may use WinRM for lateral movement.".to_string(),
            data_sources: vec![
                "Command: Command Execution".to_string(),
                "Process: Process Creation".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1021".to_string()),
        });

        // Persistence
        self.add_technique(MitreTechnique {
            id: "T1053".to_string(),
            name: "Scheduled Task/Job".to_string(),
            tactic: MitreTactic::Persistence,
            description: "Adversaries may abuse task scheduling to execute malicious code.".to_string(),
            data_sources: vec![
                "Command: Command Execution".to_string(),
                "Scheduled Job: Scheduled Job Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1053.005".to_string(),
            name: "Scheduled Task".to_string(),
            tactic: MitreTactic::Persistence,
            description: "Adversaries may abuse Windows Task Scheduler.".to_string(),
            data_sources: vec![
                "Scheduled Job: Scheduled Job Creation".to_string(),
                "Process: Process Creation".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1053".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1547".to_string(),
            name: "Boot or Logon Autostart Execution".to_string(),
            tactic: MitreTactic::Persistence,
            description: "Adversaries may configure system settings to execute programs at startup.".to_string(),
            data_sources: vec![
                "Windows Registry: Windows Registry Key Modification".to_string(),
                "File: File Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1547.001".to_string(),
            name: "Registry Run Keys / Startup Folder".to_string(),
            tactic: MitreTactic::Persistence,
            description: "Adversaries may use Run keys or startup folder for persistence.".to_string(),
            data_sources: vec![
                "Windows Registry: Windows Registry Key Modification".to_string(),
                "File: File Creation".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1547".to_string()),
        });

        // Privilege Escalation
        self.add_technique(MitreTechnique {
            id: "T1068".to_string(),
            name: "Exploitation for Privilege Escalation".to_string(),
            tactic: MitreTactic::PrivilegeEscalation,
            description: "Adversaries may exploit software vulnerabilities for privilege escalation.".to_string(),
            data_sources: vec![
                "Process: Process Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1134".to_string(),
            name: "Access Token Manipulation".to_string(),
            tactic: MitreTactic::PrivilegeEscalation,
            description: "Adversaries may modify access tokens to operate with different privileges.".to_string(),
            data_sources: vec![
                "Process: Process Metadata".to_string(),
                "Process: OS API Execution".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        // Discovery
        self.add_technique(MitreTechnique {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
            tactic: MitreTactic::Discovery,
            description: "Adversaries may attempt to discover network services.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Flow".to_string(),
                "Command: Command Execution".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1087".to_string(),
            name: "Account Discovery".to_string(),
            tactic: MitreTactic::Discovery,
            description: "Adversaries may attempt to discover accounts on a system.".to_string(),
            data_sources: vec![
                "Command: Command Execution".to_string(),
                "Process: Process Creation".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1018".to_string(),
            name: "Remote System Discovery".to_string(),
            tactic: MitreTactic::Discovery,
            description: "Adversaries may attempt to discover remote systems.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Flow".to_string(),
                "Command: Command Execution".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        // Command and Control
        self.add_technique(MitreTechnique {
            id: "T1071".to_string(),
            name: "Application Layer Protocol".to_string(),
            tactic: MitreTactic::CommandAndControl,
            description: "Adversaries may communicate using application layer protocols.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Content".to_string(),
                "Network Traffic: Network Traffic Flow".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1071.001".to_string(),
            name: "Web Protocols".to_string(),
            tactic: MitreTactic::CommandAndControl,
            description: "Adversaries may use HTTP/S for C2 communication.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Content".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1071".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1571".to_string(),
            name: "Non-Standard Port".to_string(),
            tactic: MitreTactic::CommandAndControl,
            description: "Adversaries may use non-standard ports for C2.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Flow".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        // Initial Access
        self.add_technique(MitreTechnique {
            id: "T1566".to_string(),
            name: "Phishing".to_string(),
            tactic: MitreTactic::InitialAccess,
            description: "Adversaries may send phishing messages to gain access.".to_string(),
            data_sources: vec![
                "Application Log: Application Log Content".to_string(),
                "Network Traffic: Network Traffic Content".to_string(),
            ],
            is_subtechnique: false,
            parent_id: None,
        });

        self.add_technique(MitreTechnique {
            id: "T1566.001".to_string(),
            name: "Spearphishing Attachment".to_string(),
            tactic: MitreTactic::InitialAccess,
            description: "Adversaries may send spearphishing with malicious attachments.".to_string(),
            data_sources: vec![
                "File: File Creation".to_string(),
                "Network Traffic: Network Traffic Content".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1566".to_string()),
        });

        self.add_technique(MitreTechnique {
            id: "T1566.002".to_string(),
            name: "Spearphishing Link".to_string(),
            tactic: MitreTactic::InitialAccess,
            description: "Adversaries may send spearphishing with malicious links.".to_string(),
            data_sources: vec![
                "Network Traffic: Network Traffic Content".to_string(),
            ],
            is_subtechnique: true,
            parent_id: Some("T1566".to_string()),
        });
    }

    fn initialize_mappings(&mut self) {
        // Password spraying
        self.attack_mappings.insert(
            "password_spray".to_string(),
            vec!["T1110.003".to_string()],
        );

        // Kerberoasting
        self.attack_mappings.insert(
            "kerberoast".to_string(),
            vec!["T1558.003".to_string()],
        );

        // AS-REP Roasting
        self.attack_mappings.insert(
            "asrep_roast".to_string(),
            vec!["T1558.004".to_string()],
        );

        // Credential dumping
        self.attack_mappings.insert(
            "credential_dump".to_string(),
            vec!["T1003.001".to_string(), "T1003.002".to_string(), "T1003.003".to_string()],
        );

        // DCSync
        self.attack_mappings.insert(
            "dcsync".to_string(),
            vec!["T1003.006".to_string()],
        );

        // SMB Relay
        self.attack_mappings.insert(
            "smb_relay".to_string(),
            vec!["T1557.001".to_string()],
        );

        // Pass the Hash
        self.attack_mappings.insert(
            "pass_the_hash".to_string(),
            vec!["T1550.002".to_string()],
        );

        // Lateral movement
        self.attack_mappings.insert(
            "lateral_movement".to_string(),
            vec!["T1550.002".to_string(), "T1021.002".to_string()],
        );

        // WinRM
        self.attack_mappings.insert(
            "winrm".to_string(),
            vec!["T1021.006".to_string()],
        );

        // Persistence - scheduled task
        self.attack_mappings.insert(
            "scheduled_task".to_string(),
            vec!["T1053.005".to_string()],
        );

        // Persistence - registry
        self.attack_mappings.insert(
            "registry_persistence".to_string(),
            vec!["T1547.001".to_string()],
        );

        // Privilege escalation
        self.attack_mappings.insert(
            "priv_esc".to_string(),
            vec!["T1068".to_string(), "T1134".to_string()],
        );

        // Port scanning
        self.attack_mappings.insert(
            "port_scan".to_string(),
            vec!["T1046".to_string()],
        );

        // Account enumeration
        self.attack_mappings.insert(
            "account_enum".to_string(),
            vec!["T1087".to_string()],
        );

        // Network discovery
        self.attack_mappings.insert(
            "network_discovery".to_string(),
            vec!["T1018".to_string()],
        );

        // C2 beacon
        self.attack_mappings.insert(
            "c2_beacon".to_string(),
            vec!["T1071.001".to_string()],
        );

        // Phishing
        self.attack_mappings.insert(
            "phishing".to_string(),
            vec!["T1566.001".to_string(), "T1566.002".to_string()],
        );
    }

    fn add_technique(&mut self, technique: MitreTechnique) {
        self.techniques.insert(technique.id.clone(), technique);
    }
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_technique() {
        let mapper = MitreMapper::new();

        let technique = mapper.get_technique("T1558.003");
        assert!(technique.is_some());
        assert_eq!(technique.unwrap().name, "Kerberoasting");
    }

    #[test]
    fn test_attack_mapping() {
        let mapper = MitreMapper::new();

        let techniques = mapper.get_techniques_for_attack("kerberoast");
        assert!(!techniques.is_empty());
        assert!(techniques.contains(&"T1558.003".to_string()));
    }

    #[test]
    fn test_tactic_techniques() {
        let mapper = MitreMapper::new();

        let techniques = mapper.get_techniques_for_tactic(&MitreTactic::CredentialAccess);
        assert!(!techniques.is_empty());
    }
}
