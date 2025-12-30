//! Attack Library
//!
//! Comprehensive library of attacks including MITRE ATT&CK techniques, APT playbooks,
//! and custom attack scenarios for purple team exercises.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attack library entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackLibraryEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: AttackCategory,
    pub mitre_technique: Option<MitreMapping>,
    pub difficulty: AttackDifficulty,
    pub platforms: Vec<Platform>,
    pub prerequisites: Vec<String>,
    pub parameters: Vec<AttackParameter>,
    pub detection_signatures: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackCategory {
    MitreAttack,
    APTPlaybook,
    Ransomware,
    Phishing,
    PrivilegeEscalation,
    LateralMovement,
    Exfiltration,
    Persistence,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
    pub sub_technique_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackDifficulty {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Cloud,
    Container,
    Network,
    Web,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackParameter {
    pub name: String,
    pub param_type: String,
    pub required: bool,
    pub default_value: Option<String>,
    pub description: String,
}

/// APT Playbook - Simulates real-world threat actor behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APTPlaybook {
    pub id: String,
    pub threat_actor: String,
    pub name: String,
    pub description: String,
    pub kill_chain_phases: Vec<KillChainPhase>,
    pub estimated_duration_mins: u64,
    pub detection_difficulty: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainPhase {
    pub phase: String,
    pub techniques: Vec<String>, // Attack library entry IDs
    pub duration_mins: u64,
    pub success_criteria: String,
}

/// Ransomware simulation scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareScenario {
    pub id: String,
    pub name: String,
    pub ransomware_family: String,
    pub phases: Vec<RansomwarePhase>,
    pub encryption_simulation: bool, // If true, simulate without actual encryption
    pub exfiltration_simulation: bool,
    pub lateral_movement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwarePhase {
    pub phase_name: String,
    pub techniques: Vec<String>,
    pub duration_mins: u64,
}

/// Pre-built APT playbooks
pub fn get_apt_playbooks() -> Vec<APTPlaybook> {
    vec![
        // Lazarus Group (APT38)
        APTPlaybook {
            id: "apt-lazarus".to_string(),
            threat_actor: "Lazarus Group (APT38)".to_string(),
            name: "Lazarus Financial Heist Playbook".to_string(),
            description: "Simulates Lazarus Group TTPs targeting financial institutions".to_string(),
            kill_chain_phases: vec![
                KillChainPhase {
                    phase: "Initial Access".to_string(),
                    techniques: vec!["T1566.001".to_string()], // Spearphishing Attachment
                    duration_mins: 5,
                    success_criteria: "Payload executed on target".to_string(),
                },
                KillChainPhase {
                    phase: "Persistence".to_string(),
                    techniques: vec!["T1547.001".to_string()], // Registry Run Keys
                    duration_mins: 3,
                    success_criteria: "Persistence established".to_string(),
                },
                KillChainPhase {
                    phase: "Credential Access".to_string(),
                    techniques: vec!["T1003.001".to_string()], // LSASS Memory
                    duration_mins: 5,
                    success_criteria: "Credentials harvested".to_string(),
                },
                KillChainPhase {
                    phase: "Lateral Movement".to_string(),
                    techniques: vec!["T1021.002".to_string()], // SMB/Windows Admin Shares
                    duration_mins: 10,
                    success_criteria: "Access to additional systems".to_string(),
                },
            ],
            estimated_duration_mins: 30,
            detection_difficulty: "high".to_string(),
            references: vec![
                "https://attack.mitre.org/groups/G0082/".to_string(),
            ],
        },

        // APT28 (Fancy Bear)
        APTPlaybook {
            id: "apt-apt28".to_string(),
            threat_actor: "APT28 (Fancy Bear)".to_string(),
            name: "APT28 Espionage Campaign".to_string(),
            description: "Simulates Russian APT28 espionage TTPs".to_string(),
            kill_chain_phases: vec![
                KillChainPhase {
                    phase: "Initial Access".to_string(),
                    techniques: vec!["T1566.002".to_string()], // Spearphishing Link
                    duration_mins: 5,
                    success_criteria: "User clicked link".to_string(),
                },
                KillChainPhase {
                    phase: "Execution".to_string(),
                    techniques: vec!["T1059.001".to_string()], // PowerShell
                    duration_mins: 3,
                    success_criteria: "Malicious script executed".to_string(),
                },
                KillChainPhase {
                    phase: "Discovery".to_string(),
                    techniques: vec!["T1087.002".to_string(), "T1083".to_string()], // Domain account, File discovery
                    duration_mins: 7,
                    success_criteria: "Environment reconnaissance complete".to_string(),
                },
                KillChainPhase {
                    phase: "Exfiltration".to_string(),
                    techniques: vec!["T1041".to_string()], // C2 channel
                    duration_mins: 10,
                    success_criteria: "Data staged for exfiltration".to_string(),
                },
            ],
            estimated_duration_mins: 30,
            detection_difficulty: "medium".to_string(),
            references: vec![
                "https://attack.mitre.org/groups/G0007/".to_string(),
            ],
        },

        // APT29 (Cozy Bear)
        APTPlaybook {
            id: "apt-apt29".to_string(),
            threat_actor: "APT29 (Cozy Bear)".to_string(),
            name: "APT29 Stealth Campaign".to_string(),
            description: "Simulates APT29 advanced persistence and stealth techniques".to_string(),
            kill_chain_phases: vec![
                KillChainPhase {
                    phase: "Initial Access".to_string(),
                    techniques: vec!["T1195.002".to_string()], // Supply Chain Compromise
                    duration_mins: 5,
                    success_criteria: "Compromised software installed".to_string(),
                },
                KillChainPhase {
                    phase: "Persistence".to_string(),
                    techniques: vec!["T1543.003".to_string()], // Windows Service
                    duration_mins: 5,
                    success_criteria: "Service persistence established".to_string(),
                },
                KillChainPhase {
                    phase: "Defense Evasion".to_string(),
                    techniques: vec!["T1070.001".to_string(), "T1027".to_string()], // Clear logs, Obfuscation
                    duration_mins: 5,
                    success_criteria: "Tracks covered".to_string(),
                },
                KillChainPhase {
                    phase: "Collection".to_string(),
                    techniques: vec!["T1560.001".to_string()], // Archive via utility
                    duration_mins: 10,
                    success_criteria: "Sensitive data collected".to_string(),
                },
            ],
            estimated_duration_mins: 30,
            detection_difficulty: "critical".to_string(),
            references: vec![
                "https://attack.mitre.org/groups/G0016/".to_string(),
            ],
        },
    ]
}

/// Pre-built ransomware scenarios
pub fn get_ransomware_scenarios() -> Vec<RansomwareScenario> {
    vec![
        RansomwareScenario {
            id: "ransomware-locky".to_string(),
            name: "Locky-style Ransomware Simulation".to_string(),
            ransomware_family: "Locky".to_string(),
            phases: vec![
                RansomwarePhase {
                    phase_name: "Initial Infection".to_string(),
                    techniques: vec!["T1566.001".to_string()], // Phishing attachment
                    duration_mins: 2,
                },
                RansomwarePhase {
                    phase_name: "Execution".to_string(),
                    techniques: vec!["T1204.002".to_string()], // User execution
                    duration_mins: 1,
                },
                RansomwarePhase {
                    phase_name: "Discovery".to_string(),
                    techniques: vec!["T1083".to_string(), "T1082".to_string()], // File/System discovery
                    duration_mins: 3,
                },
                RansomwarePhase {
                    phase_name: "Encryption Simulation".to_string(),
                    techniques: vec!["T1486".to_string()], // Data encrypted for impact
                    duration_mins: 5,
                },
            ],
            encryption_simulation: true,
            exfiltration_simulation: false,
            lateral_movement: false,
        },

        RansomwareScenario {
            id: "ransomware-ryuk".to_string(),
            name: "Ryuk Advanced Ransomware".to_string(),
            ransomware_family: "Ryuk".to_string(),
            phases: vec![
                RansomwarePhase {
                    phase_name: "Initial Access".to_string(),
                    techniques: vec!["T1078".to_string()], // Valid accounts
                    duration_mins: 2,
                },
                RansomwarePhase {
                    phase_name: "Credential Access".to_string(),
                    techniques: vec!["T1003.001".to_string()], // LSASS memory
                    duration_mins: 5,
                },
                RansomwarePhase {
                    phase_name: "Lateral Movement".to_string(),
                    techniques: vec!["T1021.002".to_string()], // SMB shares
                    duration_mins: 10,
                },
                RansomwarePhase {
                    phase_name: "Data Exfiltration".to_string(),
                    techniques: vec!["T1020".to_string()], // Automated exfiltration
                    duration_mins: 15,
                },
                RansomwarePhase {
                    phase_name: "Mass Encryption".to_string(),
                    techniques: vec!["T1486".to_string()], // Data encrypted
                    duration_mins: 10,
                },
            ],
            encryption_simulation: true,
            exfiltration_simulation: true,
            lateral_movement: true,
        },
    ]
}

/// Get all attack library entries
pub fn get_attack_library() -> Vec<AttackLibraryEntry> {
    vec![
        // T1566.001 - Spearphishing Attachment
        AttackLibraryEntry {
            id: "T1566.001".to_string(),
            name: "Spearphishing Attachment".to_string(),
            description: "Adversaries may send spearphishing emails with a malicious attachment".to_string(),
            category: AttackCategory::MitreAttack,
            mitre_technique: Some(MitreMapping {
                tactic: "Initial Access".to_string(),
                technique_id: "T1566".to_string(),
                technique_name: "Phishing".to_string(),
                sub_technique_id: Some("001".to_string()),
            }),
            difficulty: AttackDifficulty::Beginner,
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            prerequisites: vec!["Email server access".to_string()],
            parameters: vec![
                AttackParameter {
                    name: "target_email".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    default_value: None,
                    description: "Target email address".to_string(),
                },
                AttackParameter {
                    name: "attachment_type".to_string(),
                    param_type: "enum".to_string(),
                    required: true,
                    default_value: Some("doc".to_string()),
                    description: "Attachment file type (doc, pdf, zip)".to_string(),
                },
            ],
            detection_signatures: vec![
                "Email attachment with macros".to_string(),
                "Suspicious file extension double extension".to_string(),
            ],
            tags: vec!["phishing".to_string(), "initial-access".to_string()],
        },

        // T1003.001 - LSASS Memory
        AttackLibraryEntry {
            id: "T1003.001".to_string(),
            name: "LSASS Memory Dumping".to_string(),
            description: "Dump credentials from LSASS process memory".to_string(),
            category: AttackCategory::MitreAttack,
            mitre_technique: Some(MitreMapping {
                tactic: "Credential Access".to_string(),
                technique_id: "T1003".to_string(),
                technique_name: "OS Credential Dumping".to_string(),
                sub_technique_id: Some("001".to_string()),
            }),
            difficulty: AttackDifficulty::Intermediate,
            platforms: vec![Platform::Windows],
            prerequisites: vec!["Administrative privileges".to_string()],
            parameters: vec![
                AttackParameter {
                    name: "method".to_string(),
                    param_type: "enum".to_string(),
                    required: true,
                    default_value: Some("mimikatz".to_string()),
                    description: "Dumping method (mimikatz, procdump, comsvcs)".to_string(),
                },
            ],
            detection_signatures: vec![
                "LSASS process access".to_string(),
                "Suspicious process creating lsass dump".to_string(),
                "Security event 4656 with lsass.exe target".to_string(),
            ],
            tags: vec!["credential-access".to_string(), "lsass".to_string()],
        },

        // T1059.001 - PowerShell
        AttackLibraryEntry {
            id: "T1059.001".to_string(),
            name: "PowerShell Execution".to_string(),
            description: "Execute malicious PowerShell commands or scripts".to_string(),
            category: AttackCategory::MitreAttack,
            mitre_technique: Some(MitreMapping {
                tactic: "Execution".to_string(),
                technique_id: "T1059".to_string(),
                technique_name: "Command and Scripting Interpreter".to_string(),
                sub_technique_id: Some("001".to_string()),
            }),
            difficulty: AttackDifficulty::Beginner,
            platforms: vec![Platform::Windows],
            prerequisites: vec![],
            parameters: vec![
                AttackParameter {
                    name: "script_content".to_string(),
                    param_type: "string".to_string(),
                    required: true,
                    default_value: None,
                    description: "PowerShell script to execute".to_string(),
                },
                AttackParameter {
                    name: "obfuscate".to_string(),
                    param_type: "boolean".to_string(),
                    required: false,
                    default_value: Some("false".to_string()),
                    description: "Obfuscate the PowerShell command".to_string(),
                },
            ],
            detection_signatures: vec![
                "PowerShell with encoded command".to_string(),
                "PowerShell download cradle".to_string(),
                "ScriptBlock logging event 4104".to_string(),
            ],
            tags: vec!["execution".to_string(), "powershell".to_string(), "living-off-the-land".to_string()],
        },
    ]
}
