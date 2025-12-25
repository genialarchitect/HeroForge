//! MITRE ATT&CK Framework Integration
//!
//! Provides comprehensive MITRE ATT&CK matrix support including:
//! - Full matrix with tactics, techniques, and sub-techniques
//! - Detection mapping to techniques
//! - Coverage heatmap generation
//! - Technique details with examples and mitigations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATT&CK Tactics (Kill Chain Phases)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitreTactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    /// Get all tactics in order
    pub fn all() -> Vec<MitreTactic> {
        vec![
            MitreTactic::Reconnaissance,
            MitreTactic::ResourceDevelopment,
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
            MitreTactic::Exfiltration,
            MitreTactic::Impact,
        ]
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "Reconnaissance",
            MitreTactic::ResourceDevelopment => "Resource Development",
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
        }
    }

    /// Get MITRE ATT&CK ID
    pub fn id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "The adversary is trying to gather information they can use to plan future operations.",
            MitreTactic::ResourceDevelopment => "The adversary is trying to establish resources they can use to support operations.",
            MitreTactic::InitialAccess => "The adversary is trying to get into your network.",
            MitreTactic::Execution => "The adversary is trying to run malicious code.",
            MitreTactic::Persistence => "The adversary is trying to maintain their foothold.",
            MitreTactic::PrivilegeEscalation => "The adversary is trying to gain higher-level permissions.",
            MitreTactic::DefenseEvasion => "The adversary is trying to avoid being detected.",
            MitreTactic::CredentialAccess => "The adversary is trying to steal account names and passwords.",
            MitreTactic::Discovery => "The adversary is trying to figure out your environment.",
            MitreTactic::LateralMovement => "The adversary is trying to move through your environment.",
            MitreTactic::Collection => "The adversary is trying to gather data of interest to their goal.",
            MitreTactic::CommandAndControl => "The adversary is trying to communicate with compromised systems to control them.",
            MitreTactic::Exfiltration => "The adversary is trying to steal data.",
            MitreTactic::Impact => "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(" ", "_").replace("-", "_").as_str() {
            "reconnaissance" | "ta0043" => Some(MitreTactic::Reconnaissance),
            "resource_development" | "ta0042" => Some(MitreTactic::ResourceDevelopment),
            "initial_access" | "ta0001" => Some(MitreTactic::InitialAccess),
            "execution" | "ta0002" => Some(MitreTactic::Execution),
            "persistence" | "ta0003" => Some(MitreTactic::Persistence),
            "privilege_escalation" | "ta0004" => Some(MitreTactic::PrivilegeEscalation),
            "defense_evasion" | "ta0005" => Some(MitreTactic::DefenseEvasion),
            "credential_access" | "ta0006" => Some(MitreTactic::CredentialAccess),
            "discovery" | "ta0007" => Some(MitreTactic::Discovery),
            "lateral_movement" | "ta0008" => Some(MitreTactic::LateralMovement),
            "collection" | "ta0009" => Some(MitreTactic::Collection),
            "command_and_control" | "ta0011" => Some(MitreTactic::CommandAndControl),
            "exfiltration" | "ta0010" => Some(MitreTactic::Exfiltration),
            "impact" | "ta0040" => Some(MitreTactic::Impact),
            _ => None,
        }
    }
}

impl std::fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Platform targets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Cloud,
    Azure,
    Aws,
    Gcp,
    Office365,
    SaaS,
    Network,
    Containers,
    Kubernetes,
    IaaS,
    Identity,
}

impl Platform {
    pub fn all() -> Vec<Platform> {
        vec![
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Cloud,
            Platform::Azure,
            Platform::Aws,
            Platform::Gcp,
            Platform::Office365,
            Platform::SaaS,
            Platform::Network,
            Platform::Containers,
            Platform::Kubernetes,
            Platform::IaaS,
            Platform::Identity,
        ]
    }
}

/// MITRE ATT&CK Technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g., T1566)
    pub technique_id: String,
    /// Technique name
    pub name: String,
    /// Primary tactic
    pub tactic: MitreTactic,
    /// Additional tactics this technique applies to
    pub additional_tactics: Vec<MitreTactic>,
    /// Description
    pub description: String,
    /// Detection strategies
    pub detection: Vec<String>,
    /// Applicable platforms
    pub platforms: Vec<Platform>,
    /// Data sources for detection
    pub data_sources: Vec<String>,
    /// Mitigations
    pub mitigations: Vec<MitreMitigation>,
    /// Sub-techniques
    pub sub_techniques: Vec<MitreSubTechnique>,
    /// Related techniques
    pub related_techniques: Vec<String>,
    /// Example procedures
    pub examples: Vec<TechniqueExample>,
    /// Is this a sub-technique?
    pub is_subtechnique: bool,
    /// Parent technique ID (for sub-techniques)
    pub parent_id: Option<String>,
    /// URL to MITRE ATT&CK page
    pub url: String,
    /// Last modified date
    pub modified: DateTime<Utc>,
}

/// MITRE ATT&CK Sub-Technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreSubTechnique {
    /// Sub-technique ID (e.g., T1566.001)
    pub technique_id: String,
    /// Sub-technique name
    pub name: String,
    /// Description
    pub description: String,
    /// Detection strategies
    pub detection: Vec<String>,
    /// Applicable platforms
    pub platforms: Vec<Platform>,
    /// Mitigations
    pub mitigations: Vec<String>,
}

/// MITRE ATT&CK Mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMitigation {
    /// Mitigation ID (e.g., M1049)
    pub mitigation_id: String,
    /// Mitigation name
    pub name: String,
    /// Description
    pub description: String,
}

/// Example of technique usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueExample {
    /// Name of threat actor or malware
    pub name: String,
    /// Description of usage
    pub description: String,
    /// Type (threat_group, malware, tool)
    pub example_type: String,
}

/// Detection mapping to MITRE ATT&CK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMapping {
    pub id: String,
    /// Detection name/title
    pub detection_name: String,
    /// Detection query or signature
    pub detection_query: Option<String>,
    /// Mapped technique IDs
    pub technique_ids: Vec<String>,
    /// Data sources used
    pub data_sources: Vec<String>,
    /// Detection type (signature, behavioral, anomaly)
    pub detection_type: String,
    /// Coverage level (low, medium, high)
    pub coverage_level: CoverageLevel,
    /// Notes
    pub notes: Option<String>,
    /// Created by
    pub user_id: String,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Coverage level for detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    None,
    Low,
    Medium,
    High,
}

impl CoverageLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(CoverageLevel::None),
            "low" => Some(CoverageLevel::Low),
            "medium" | "med" => Some(CoverageLevel::Medium),
            "high" => Some(CoverageLevel::High),
            _ => None,
        }
    }

    pub fn to_color(&self) -> &'static str {
        match self {
            CoverageLevel::None => "#808080",
            CoverageLevel::Low => "#ff6b6b",
            CoverageLevel::Medium => "#feca57",
            CoverageLevel::High => "#48dbfb",
        }
    }
}

impl std::fmt::Display for CoverageLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CoverageLevel::None => "none",
            CoverageLevel::Low => "low",
            CoverageLevel::Medium => "medium",
            CoverageLevel::High => "high",
        };
        write!(f, "{}", s)
    }
}

/// Coverage heatmap data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageHeatmap {
    /// Technique ID to coverage level mapping
    pub technique_coverage: HashMap<String, CoverageLevel>,
    /// Tactic-level statistics
    pub tactic_stats: HashMap<String, TacticCoverageStats>,
    /// Overall coverage percentage
    pub overall_coverage: f64,
    /// Total techniques
    pub total_techniques: usize,
    /// Covered techniques count
    pub covered_techniques: usize,
    /// Generated at
    pub generated_at: DateTime<Utc>,
}

/// Tactic-level coverage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverageStats {
    pub tactic: String,
    pub tactic_id: String,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub high_coverage: usize,
    pub medium_coverage: usize,
    pub low_coverage: usize,
    pub no_coverage: usize,
    pub coverage_percentage: f64,
}

/// ATT&CK Matrix representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMatrix {
    /// Matrix name
    pub name: String,
    /// Matrix version
    pub version: String,
    /// Tactics in order
    pub tactics: Vec<TacticColumn>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Column in the ATT&CK matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticColumn {
    pub tactic: MitreTactic,
    pub techniques: Vec<TechniqueCell>,
}

/// Cell in the ATT&CK matrix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCell {
    pub technique_id: String,
    pub name: String,
    pub sub_technique_count: usize,
    pub coverage: CoverageLevel,
    pub detection_count: usize,
}

/// Request to create detection mapping
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDetectionMappingRequest {
    pub detection_name: String,
    pub detection_query: Option<String>,
    pub technique_ids: Vec<String>,
    pub data_sources: Option<Vec<String>>,
    pub detection_type: Option<String>,
    pub coverage_level: Option<CoverageLevel>,
    pub notes: Option<String>,
}

/// Built-in MITRE ATT&CK techniques database
pub struct MitreDatabase;

impl MitreDatabase {
    /// Get all built-in techniques
    pub fn get_all_techniques() -> Vec<MitreTechnique> {
        let mut techniques = Vec::new();

        // Initial Access techniques
        techniques.push(MitreTechnique {
            technique_id: "T1566".to_string(),
            name: "Phishing".to_string(),
            tactic: MitreTactic::InitialAccess,
            additional_tactics: vec![],
            description: "Adversaries may send phishing messages to gain access to victim systems.".to_string(),
            detection: vec![
                "Monitor for suspicious email attachments".to_string(),
                "Analyze email headers for spoofing indicators".to_string(),
                "Track link clicks from email clients".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS, Platform::Office365],
            data_sources: vec!["Email", "Network Traffic", "Application Log"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1049".to_string(),
                    name: "Antivirus/Antimalware".to_string(),
                    description: "Use antivirus to detect and block malicious attachments".to_string(),
                },
                MitreMitigation {
                    mitigation_id: "M1031".to_string(),
                    name: "Network Intrusion Prevention".to_string(),
                    description: "Use network intrusion prevention to block malicious downloads".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1566.001".to_string(),
                    name: "Spearphishing Attachment".to_string(),
                    description: "Adversaries may send spearphishing emails with a malicious attachment.".to_string(),
                    detection: vec!["Monitor email attachments".to_string()],
                    platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
                    mitigations: vec!["Email filtering".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1566.002".to_string(),
                    name: "Spearphishing Link".to_string(),
                    description: "Adversaries may send spearphishing emails with a malicious link.".to_string(),
                    detection: vec!["Monitor for URL clicks".to_string()],
                    platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
                    mitigations: vec!["User training".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1566.003".to_string(),
                    name: "Spearphishing via Service".to_string(),
                    description: "Adversaries may send spearphishing via third-party services.".to_string(),
                    detection: vec!["Monitor messaging platforms".to_string()],
                    platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS, Platform::SaaS],
                    mitigations: vec!["Restrict web-based content".to_string()],
                },
            ],
            related_techniques: vec!["T1204".to_string(), "T1534".to_string()],
            examples: vec![
                TechniqueExample {
                    name: "APT28".to_string(),
                    description: "APT28 has used spearphishing with malicious attachments".to_string(),
                    example_type: "threat_group".to_string(),
                },
            ],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1566".to_string(),
            modified: Utc::now(),
        });

        // Credential Access techniques
        techniques.push(MitreTechnique {
            technique_id: "T1003".to_string(),
            name: "OS Credential Dumping".to_string(),
            tactic: MitreTactic::CredentialAccess,
            additional_tactics: vec![],
            description: "Adversaries may attempt to dump credentials to obtain account login and credential material.".to_string(),
            detection: vec![
                "Monitor for LSASS access".to_string(),
                "Detect Mimikatz execution".to_string(),
                "Watch for SAM database access".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux],
            data_sources: vec!["Process", "Command", "Windows Registry"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1043".to_string(),
                    name: "Credential Access Protection".to_string(),
                    description: "Use Credential Guard to protect LSASS".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1003.001".to_string(),
                    name: "LSASS Memory".to_string(),
                    description: "Adversaries may dump LSASS memory to obtain credentials.".to_string(),
                    detection: vec!["Monitor LSASS process access".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Credential Guard".to_string()],
                },
            ],
            related_techniques: vec!["T1550".to_string()],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1003".to_string(),
            modified: Utc::now(),
        });

        // Lateral Movement techniques
        techniques.push(MitreTechnique {
            technique_id: "T1021".to_string(),
            name: "Remote Services".to_string(),
            tactic: MitreTactic::LateralMovement,
            additional_tactics: vec![],
            description: "Adversaries may use valid accounts to log into services for lateral movement.".to_string(),
            detection: vec![
                "Monitor authentication logs".to_string(),
                "Track remote login events".to_string(),
                "Analyze network connections".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["Logon Session", "Network Traffic"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1032".to_string(),
                    name: "Multi-factor Authentication".to_string(),
                    description: "Require MFA for remote access".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1021.001".to_string(),
                    name: "Remote Desktop Protocol".to_string(),
                    description: "Adversaries may use RDP for lateral movement.".to_string(),
                    detection: vec!["Monitor RDP connections".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Network segmentation".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1021.002".to_string(),
                    name: "SMB/Windows Admin Shares".to_string(),
                    description: "Adversaries may use SMB for lateral movement.".to_string(),
                    detection: vec!["Monitor SMB traffic".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Disable admin shares".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1021.004".to_string(),
                    name: "SSH".to_string(),
                    description: "Adversaries may use SSH for lateral movement.".to_string(),
                    detection: vec!["Monitor SSH connections".to_string()],
                    platforms: vec![Platform::Linux, Platform::MacOS],
                    mitigations: vec!["SSH key management".to_string()],
                },
            ],
            related_techniques: vec!["T1078".to_string()],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1021".to_string(),
            modified: Utc::now(),
        });

        // Data Exfiltration techniques
        techniques.push(MitreTechnique {
            technique_id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: MitreTactic::Exfiltration,
            additional_tactics: vec![],
            description: "Adversaries may steal data by exfiltrating it over an existing C2 channel.".to_string(),
            detection: vec![
                "Monitor outbound traffic volume".to_string(),
                "Analyze C2 communication patterns".to_string(),
                "Track file access before network activity".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["Network Traffic", "Command"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1031".to_string(),
                    name: "Network Intrusion Prevention".to_string(),
                    description: "Use network monitoring to detect exfiltration".to_string(),
                },
            ],
            sub_techniques: vec![],
            related_techniques: vec!["T1071".to_string()],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1041".to_string(),
            modified: Utc::now(),
        });

        // Persistence techniques
        techniques.push(MitreTechnique {
            technique_id: "T1547".to_string(),
            name: "Boot or Logon Autostart Execution".to_string(),
            tactic: MitreTactic::Persistence,
            additional_tactics: vec![MitreTactic::PrivilegeEscalation],
            description: "Adversaries may configure system settings to automatically execute malware on startup.".to_string(),
            detection: vec![
                "Monitor registry Run keys".to_string(),
                "Track startup folder modifications".to_string(),
                "Analyze scheduled tasks".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["Windows Registry", "File", "Command"].into_iter().map(String::from).collect(),
            mitigations: vec![],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1547.001".to_string(),
                    name: "Registry Run Keys / Startup Folder".to_string(),
                    description: "Adversaries may use registry Run keys or Startup folder for persistence.".to_string(),
                    detection: vec!["Monitor registry Run keys".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Restrict registry permissions".to_string()],
                },
            ],
            related_techniques: vec![],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1547".to_string(),
            modified: Utc::now(),
        });

        // Execution techniques
        techniques.push(MitreTechnique {
            technique_id: "T1059".to_string(),
            name: "Command and Scripting Interpreter".to_string(),
            tactic: MitreTactic::Execution,
            additional_tactics: vec![],
            description: "Adversaries may abuse command and script interpreters to execute commands.".to_string(),
            detection: vec![
                "Monitor command-line arguments".to_string(),
                "Track script execution".to_string(),
                "Analyze process creation events".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["Process", "Command", "Script"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1042".to_string(),
                    name: "Disable or Remove Feature or Program".to_string(),
                    description: "Remove unnecessary scripting engines".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1059.001".to_string(),
                    name: "PowerShell".to_string(),
                    description: "Adversaries may abuse PowerShell for execution.".to_string(),
                    detection: vec!["Monitor PowerShell logs".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Constrained Language Mode".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1059.003".to_string(),
                    name: "Windows Command Shell".to_string(),
                    description: "Adversaries may abuse cmd.exe for execution.".to_string(),
                    detection: vec!["Monitor cmd.exe activity".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Command-line logging".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1059.004".to_string(),
                    name: "Unix Shell".to_string(),
                    description: "Adversaries may abuse Unix shell for execution.".to_string(),
                    detection: vec!["Monitor shell commands".to_string()],
                    platforms: vec![Platform::Linux, Platform::MacOS],
                    mitigations: vec!["Bash history logging".to_string()],
                },
            ],
            related_techniques: vec![],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1059".to_string(),
            modified: Utc::now(),
        });

        // Defense Evasion techniques
        techniques.push(MitreTechnique {
            technique_id: "T1070".to_string(),
            name: "Indicator Removal".to_string(),
            tactic: MitreTactic::DefenseEvasion,
            additional_tactics: vec![],
            description: "Adversaries may delete or modify artifacts to hide malicious activity.".to_string(),
            detection: vec![
                "Monitor for log deletion".to_string(),
                "Track file modifications in sensitive locations".to_string(),
                "Detect event log clearing".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["File", "Windows Event Log", "Command"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1029".to_string(),
                    name: "Remote Data Storage".to_string(),
                    description: "Store logs remotely to prevent local tampering".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1070.001".to_string(),
                    name: "Clear Windows Event Logs".to_string(),
                    description: "Adversaries may clear Windows Event Logs to hide activity.".to_string(),
                    detection: vec!["Monitor event log clearing".to_string()],
                    platforms: vec![Platform::Windows],
                    mitigations: vec!["Forward logs to SIEM".to_string()],
                },
            ],
            related_techniques: vec![],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1070".to_string(),
            modified: Utc::now(),
        });

        // Discovery techniques
        techniques.push(MitreTechnique {
            technique_id: "T1082".to_string(),
            name: "System Information Discovery".to_string(),
            tactic: MitreTactic::Discovery,
            additional_tactics: vec![],
            description: "An adversary may attempt to get detailed information about the operating system and hardware.".to_string(),
            detection: vec![
                "Monitor for system information enumeration commands".to_string(),
                "Track WMI queries".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["Process", "Command"].into_iter().map(String::from).collect(),
            mitigations: vec![],
            sub_techniques: vec![],
            related_techniques: vec![],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1082".to_string(),
            modified: Utc::now(),
        });

        // Command and Control techniques
        techniques.push(MitreTechnique {
            technique_id: "T1071".to_string(),
            name: "Application Layer Protocol".to_string(),
            tactic: MitreTactic::CommandAndControl,
            additional_tactics: vec![],
            description: "Adversaries may communicate using application layer protocols to avoid detection.".to_string(),
            detection: vec![
                "Monitor for unusual DNS queries".to_string(),
                "Analyze HTTP/HTTPS traffic patterns".to_string(),
                "Detect beaconing behavior".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS, Platform::Network],
            data_sources: vec!["Network Traffic"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1031".to_string(),
                    name: "Network Intrusion Prevention".to_string(),
                    description: "Use network monitoring to detect C2 traffic".to_string(),
                },
            ],
            sub_techniques: vec![
                MitreSubTechnique {
                    technique_id: "T1071.001".to_string(),
                    name: "Web Protocols".to_string(),
                    description: "Adversaries may use HTTP/HTTPS for C2.".to_string(),
                    detection: vec!["Monitor HTTP traffic".to_string()],
                    platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
                    mitigations: vec!["SSL inspection".to_string()],
                },
                MitreSubTechnique {
                    technique_id: "T1071.004".to_string(),
                    name: "DNS".to_string(),
                    description: "Adversaries may use DNS for C2.".to_string(),
                    detection: vec!["Monitor DNS queries".to_string()],
                    platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
                    mitigations: vec!["DNS filtering".to_string()],
                },
            ],
            related_techniques: vec![],
            examples: vec![],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1071".to_string(),
            modified: Utc::now(),
        });

        // Impact techniques
        techniques.push(MitreTechnique {
            technique_id: "T1486".to_string(),
            name: "Data Encrypted for Impact".to_string(),
            tactic: MitreTactic::Impact,
            additional_tactics: vec![],
            description: "Adversaries may encrypt data on target systems to interrupt availability.".to_string(),
            detection: vec![
                "Monitor for mass file encryption".to_string(),
                "Track file extension changes".to_string(),
                "Detect ransomware indicators".to_string(),
            ],
            platforms: vec![Platform::Windows, Platform::Linux, Platform::MacOS],
            data_sources: vec!["File", "Process"].into_iter().map(String::from).collect(),
            mitigations: vec![
                MitreMitigation {
                    mitigation_id: "M1053".to_string(),
                    name: "Data Backup".to_string(),
                    description: "Maintain offline backups".to_string(),
                },
            ],
            sub_techniques: vec![],
            related_techniques: vec![],
            examples: vec![
                TechniqueExample {
                    name: "WannaCry".to_string(),
                    description: "WannaCry encrypts files and demands ransom".to_string(),
                    example_type: "malware".to_string(),
                },
            ],
            is_subtechnique: false,
            parent_id: None,
            url: "https://attack.mitre.org/techniques/T1486".to_string(),
            modified: Utc::now(),
        });

        techniques
    }

    /// Get technique by ID
    pub fn get_technique(technique_id: &str) -> Option<MitreTechnique> {
        Self::get_all_techniques()
            .into_iter()
            .find(|t| t.technique_id == technique_id)
    }

    /// Get techniques by tactic
    pub fn get_techniques_by_tactic(tactic: MitreTactic) -> Vec<MitreTechnique> {
        Self::get_all_techniques()
            .into_iter()
            .filter(|t| t.tactic == tactic || t.additional_tactics.contains(&tactic))
            .collect()
    }

    /// Build ATT&CK matrix
    pub fn build_matrix(coverage: Option<&HashMap<String, CoverageLevel>>) -> AttackMatrix {
        let empty_coverage = HashMap::new();
        let coverage = coverage.unwrap_or(&empty_coverage);

        let techniques = Self::get_all_techniques();

        let tactics: Vec<TacticColumn> = MitreTactic::all()
            .into_iter()
            .map(|tactic| {
                let tactic_techniques: Vec<TechniqueCell> = techniques
                    .iter()
                    .filter(|t| t.tactic == tactic || t.additional_tactics.contains(&tactic))
                    .map(|t| TechniqueCell {
                        technique_id: t.technique_id.clone(),
                        name: t.name.clone(),
                        sub_technique_count: t.sub_techniques.len(),
                        coverage: coverage.get(&t.technique_id).copied().unwrap_or(CoverageLevel::None),
                        detection_count: 0,
                    })
                    .collect();

                TacticColumn {
                    tactic,
                    techniques: tactic_techniques,
                }
            })
            .collect();

        AttackMatrix {
            name: "Enterprise ATT&CK".to_string(),
            version: "14.0".to_string(),
            tactics,
            last_updated: Utc::now(),
        }
    }

    /// Calculate coverage heatmap from detection mappings
    pub fn calculate_coverage(mappings: &[DetectionMapping]) -> CoverageHeatmap {
        let techniques = Self::get_all_techniques();
        let mut technique_coverage: HashMap<String, CoverageLevel> = HashMap::new();

        // Initialize all techniques with no coverage
        for tech in &techniques {
            technique_coverage.insert(tech.technique_id.clone(), CoverageLevel::None);
            for sub in &tech.sub_techniques {
                technique_coverage.insert(sub.technique_id.clone(), CoverageLevel::None);
            }
        }

        // Apply coverage from mappings
        for mapping in mappings {
            for tech_id in &mapping.technique_ids {
                let current = technique_coverage.get(tech_id).copied().unwrap_or(CoverageLevel::None);
                // Take the higher coverage level
                if mapping.coverage_level > current {
                    technique_coverage.insert(tech_id.clone(), mapping.coverage_level);
                }
            }
        }

        // Calculate tactic statistics
        let mut tactic_stats: HashMap<String, TacticCoverageStats> = HashMap::new();

        for tactic in MitreTactic::all() {
            let tactic_techniques: Vec<&MitreTechnique> = techniques
                .iter()
                .filter(|t| t.tactic == tactic)
                .collect();

            let total = tactic_techniques.len();
            let mut high = 0;
            let mut medium = 0;
            let mut low = 0;
            let mut none = 0;

            for tech in &tactic_techniques {
                match technique_coverage.get(&tech.technique_id).unwrap_or(&CoverageLevel::None) {
                    CoverageLevel::High => high += 1,
                    CoverageLevel::Medium => medium += 1,
                    CoverageLevel::Low => low += 1,
                    CoverageLevel::None => none += 1,
                }
            }

            let covered = high + medium + low;
            let coverage_pct = if total > 0 {
                (covered as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            tactic_stats.insert(
                tactic.id().to_string(),
                TacticCoverageStats {
                    tactic: tactic.display_name().to_string(),
                    tactic_id: tactic.id().to_string(),
                    total_techniques: total,
                    covered_techniques: covered,
                    high_coverage: high,
                    medium_coverage: medium,
                    low_coverage: low,
                    no_coverage: none,
                    coverage_percentage: coverage_pct,
                },
            );
        }

        // Calculate overall coverage
        let total_techniques = technique_coverage.len();
        let covered_techniques = technique_coverage
            .values()
            .filter(|&c| *c != CoverageLevel::None)
            .count();

        let overall_coverage = if total_techniques > 0 {
            (covered_techniques as f64 / total_techniques as f64) * 100.0
        } else {
            0.0
        };

        CoverageHeatmap {
            technique_coverage,
            tactic_stats,
            overall_coverage,
            total_techniques,
            covered_techniques,
            generated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tactic_parsing() {
        assert_eq!(MitreTactic::from_str("initial_access"), Some(MitreTactic::InitialAccess));
        assert_eq!(MitreTactic::from_str("TA0001"), Some(MitreTactic::InitialAccess));
        assert_eq!(MitreTactic::from_str("lateral_movement"), Some(MitreTactic::LateralMovement));
    }

    #[test]
    fn test_technique_lookup() {
        let technique = MitreDatabase::get_technique("T1566");
        assert!(technique.is_some());
        assert_eq!(technique.unwrap().name, "Phishing");
    }

    #[test]
    fn test_matrix_building() {
        let matrix = MitreDatabase::build_matrix(None);
        assert!(!matrix.tactics.is_empty());
        assert_eq!(matrix.tactics.len(), 14); // 14 tactics
    }

    #[test]
    fn test_coverage_calculation() {
        let mappings = vec![
            DetectionMapping {
                id: "1".to_string(),
                detection_name: "Phishing Detection".to_string(),
                detection_query: None,
                technique_ids: vec!["T1566".to_string()],
                data_sources: vec![],
                detection_type: "signature".to_string(),
                coverage_level: CoverageLevel::High,
                notes: None,
                user_id: "user1".to_string(),
                created_at: Utc::now(),
            },
        ];

        let heatmap = MitreDatabase::calculate_coverage(&mappings);
        assert_eq!(
            heatmap.technique_coverage.get("T1566"),
            Some(&CoverageLevel::High)
        );
    }
}
