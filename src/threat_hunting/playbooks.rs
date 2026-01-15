//! Threat Hunting Playbooks
//!
//! Provides structured hunting procedures including:
//! - Playbook templates for common hunts (credential theft, lateral movement, data exfil, persistence)
//! - Step-by-step hunting procedures
//! - Query templates for each step
//! - Evidence collection checkpoints
//! - Built-in playbooks for common threat hunting scenarios

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::mitre::MitreTactic;

/// Playbook category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookCategory {
    CredentialTheft,
    LateralMovement,
    DataExfiltration,
    Persistence,
    CommandAndControl,
    InitialAccess,
    PrivilegeEscalation,
    DefenseEvasion,
    Ransomware,
    InsiderThreat,
    SupplyChain,
    Custom,
}

impl PlaybookCategory {
    pub fn all() -> Vec<PlaybookCategory> {
        vec![
            PlaybookCategory::CredentialTheft,
            PlaybookCategory::LateralMovement,
            PlaybookCategory::DataExfiltration,
            PlaybookCategory::Persistence,
            PlaybookCategory::CommandAndControl,
            PlaybookCategory::InitialAccess,
            PlaybookCategory::PrivilegeEscalation,
            PlaybookCategory::DefenseEvasion,
            PlaybookCategory::Ransomware,
            PlaybookCategory::InsiderThreat,
            PlaybookCategory::SupplyChain,
            PlaybookCategory::Custom,
        ]
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            PlaybookCategory::CredentialTheft => "Credential Theft",
            PlaybookCategory::LateralMovement => "Lateral Movement",
            PlaybookCategory::DataExfiltration => "Data Exfiltration",
            PlaybookCategory::Persistence => "Persistence",
            PlaybookCategory::CommandAndControl => "Command and Control",
            PlaybookCategory::InitialAccess => "Initial Access",
            PlaybookCategory::PrivilegeEscalation => "Privilege Escalation",
            PlaybookCategory::DefenseEvasion => "Defense Evasion",
            PlaybookCategory::Ransomware => "Ransomware",
            PlaybookCategory::InsiderThreat => "Insider Threat",
            PlaybookCategory::SupplyChain => "Supply Chain",
            PlaybookCategory::Custom => "Custom",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace(" ", "_").replace("-", "_").as_str() {
            "credential_theft" | "credentials" => Some(PlaybookCategory::CredentialTheft),
            "lateral_movement" | "lateral" => Some(PlaybookCategory::LateralMovement),
            "data_exfiltration" | "exfiltration" | "exfil" => Some(PlaybookCategory::DataExfiltration),
            "persistence" => Some(PlaybookCategory::Persistence),
            "command_and_control" | "c2" | "c&c" => Some(PlaybookCategory::CommandAndControl),
            "initial_access" | "initial" => Some(PlaybookCategory::InitialAccess),
            "privilege_escalation" | "privesc" => Some(PlaybookCategory::PrivilegeEscalation),
            "defense_evasion" | "evasion" => Some(PlaybookCategory::DefenseEvasion),
            "ransomware" => Some(PlaybookCategory::Ransomware),
            "insider_threat" | "insider" => Some(PlaybookCategory::InsiderThreat),
            "supply_chain" | "supplychain" => Some(PlaybookCategory::SupplyChain),
            "custom" => Some(PlaybookCategory::Custom),
            _ => None,
        }
    }
}

impl std::fmt::Display for PlaybookCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Difficulty level for playbook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifficultyLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

impl DifficultyLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "beginner" | "easy" => Some(DifficultyLevel::Beginner),
            "intermediate" | "medium" => Some(DifficultyLevel::Intermediate),
            "advanced" | "hard" => Some(DifficultyLevel::Advanced),
            "expert" => Some(DifficultyLevel::Expert),
            _ => None,
        }
    }
}

impl std::fmt::Display for DifficultyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DifficultyLevel::Beginner => "beginner",
            DifficultyLevel::Intermediate => "intermediate",
            DifficultyLevel::Advanced => "advanced",
            DifficultyLevel::Expert => "expert",
        };
        write!(f, "{}", s)
    }
}

/// Status of a hunting step
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    NotStarted,
    InProgress,
    Completed,
    Skipped,
    Blocked,
}

impl StepStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "not_started" | "pending" => Some(StepStatus::NotStarted),
            "in_progress" | "running" => Some(StepStatus::InProgress),
            "completed" | "done" => Some(StepStatus::Completed),
            "skipped" => Some(StepStatus::Skipped),
            "blocked" => Some(StepStatus::Blocked),
            _ => None,
        }
    }
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StepStatus::NotStarted => "not_started",
            StepStatus::InProgress => "in_progress",
            StepStatus::Completed => "completed",
            StepStatus::Skipped => "skipped",
            StepStatus::Blocked => "blocked",
        };
        write!(f, "{}", s)
    }
}

/// Hunting session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Cancelled,
}

impl SessionStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" | "running" => Some(SessionStatus::Active),
            "paused" => Some(SessionStatus::Paused),
            "completed" | "done" => Some(SessionStatus::Completed),
            "cancelled" | "canceled" => Some(SessionStatus::Cancelled),
            _ => None,
        }
    }
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SessionStatus::Active => "active",
            SessionStatus::Paused => "paused",
            SessionStatus::Completed => "completed",
            SessionStatus::Cancelled => "cancelled",
        };
        write!(f, "{}", s)
    }
}

/// Query type for hunting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Splunk,
    Elastic,
    Kusto,  // Azure Data Explorer / Sentinel KQL
    Sigma,  // Generic Sigma rule
    Sql,
    PowerShell,
    Bash,
    Custom,
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            QueryType::Splunk => "splunk",
            QueryType::Elastic => "elastic",
            QueryType::Kusto => "kusto",
            QueryType::Sigma => "sigma",
            QueryType::Sql => "sql",
            QueryType::PowerShell => "powershell",
            QueryType::Bash => "bash",
            QueryType::Custom => "custom",
        };
        write!(f, "{}", s)
    }
}

/// Query template for hunting step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTemplate {
    /// Query type/language
    pub query_type: QueryType,
    /// Query string
    pub query: String,
    /// Description of what this query does
    pub description: String,
    /// Data sources required
    pub data_sources: Vec<String>,
    /// Expected fields in results
    pub expected_fields: Vec<String>,
    /// Time range suggestion (e.g., "7d", "24h")
    pub suggested_timerange: Option<String>,
}

/// Evidence checkpoint in playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCheckpoint {
    /// Checkpoint ID
    pub id: String,
    /// Name of the checkpoint
    pub name: String,
    /// Description of what evidence to collect
    pub description: String,
    /// Types of evidence to gather
    pub evidence_types: Vec<String>,
    /// Is this checkpoint required?
    pub required: bool,
}

/// Hunting playbook step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Step number (1-indexed)
    pub step_number: u32,
    /// Step title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Objective of this step
    pub objective: String,
    /// Expected duration (e.g., "30m", "2h")
    pub expected_duration: Option<String>,
    /// Queries to execute
    pub queries: Vec<QueryTemplate>,
    /// Evidence checkpoints
    pub evidence_checkpoints: Vec<EvidenceCheckpoint>,
    /// What to look for (indicators)
    pub indicators_to_find: Vec<String>,
    /// Decision points (branching logic)
    pub decision_points: Vec<DecisionPoint>,
    /// Related MITRE techniques
    pub mitre_techniques: Vec<String>,
    /// Prerequisites (step numbers that must be completed first)
    pub prerequisites: Vec<u32>,
    /// Notes and tips
    pub notes: Option<String>,
}

/// Decision point for branching in playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionPoint {
    /// Condition description
    pub condition: String,
    /// Action if condition is true
    pub if_true: String,
    /// Action if condition is false
    pub if_false: String,
}

/// Threat hunting playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingPlaybook {
    pub id: String,
    /// Playbook name
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Category
    pub category: PlaybookCategory,
    /// Difficulty level
    pub difficulty: DifficultyLevel,
    /// Estimated total duration
    pub estimated_duration: String,
    /// Steps in order
    pub steps: Vec<PlaybookStep>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Related MITRE ATT&CK tactics
    pub mitre_tactics: Vec<MitreTactic>,
    /// Related MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Is this a built-in playbook?
    pub is_builtin: bool,
    /// Author user ID (null for built-in)
    pub user_id: Option<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
    /// Version
    pub version: String,
}

/// Hunting session instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingSession {
    pub id: String,
    /// Associated playbook ID
    pub playbook_id: String,
    /// Session status
    pub status: SessionStatus,
    /// Current step number
    pub current_step: u32,
    /// Step progress
    pub step_progress: Vec<StepProgress>,
    /// Findings discovered during hunt
    pub findings: Vec<HuntingFinding>,
    /// Session notes
    pub notes: Vec<SessionNote>,
    /// Time tracking
    pub time_spent_minutes: u32,
    /// Started at
    pub started_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// User ID
    pub user_id: String,
    /// Scope/target of the hunt
    pub scope: Option<String>,
    /// Hypothesis being tested
    pub hypothesis: Option<String>,
}

/// Progress on a single step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepProgress {
    pub step_number: u32,
    pub status: StepStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub query_results: Vec<QueryResult>,
    pub evidence_collected: Vec<CollectedEvidence>,
    pub notes: Option<String>,
}

/// Result of executing a query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub query_type: QueryType,
    pub executed_at: DateTime<Utc>,
    pub result_count: u32,
    pub sample_results: Option<serde_json::Value>,
    pub notes: Option<String>,
}

/// Evidence collected during hunting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedEvidence {
    pub checkpoint_id: String,
    pub evidence_type: String,
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub collected_at: DateTime<Utc>,
    pub file_path: Option<String>,
}

/// Finding discovered during hunt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntingFinding {
    pub id: String,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity (info, low, medium, high, critical)
    pub severity: String,
    /// Step number where found
    pub found_at_step: u32,
    /// Related IOC IDs
    pub related_iocs: Vec<String>,
    /// Related MITRE techniques
    pub mitre_techniques: Vec<String>,
    /// Evidence supporting this finding
    pub evidence: Vec<CollectedEvidence>,
    /// Recommended actions
    pub recommendations: Vec<String>,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Session note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNote {
    pub id: String,
    pub step_number: Option<u32>,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

/// Request to create a playbook
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePlaybookRequest {
    pub name: String,
    pub description: String,
    pub category: PlaybookCategory,
    pub difficulty: Option<DifficultyLevel>,
    pub estimated_duration: Option<String>,
    pub steps: Vec<CreatePlaybookStepRequest>,
    pub tags: Option<Vec<String>>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
}

/// Request to create a playbook step
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePlaybookStepRequest {
    pub title: String,
    pub description: String,
    pub objective: String,
    pub expected_duration: Option<String>,
    pub queries: Option<Vec<QueryTemplate>>,
    pub evidence_checkpoints: Option<Vec<EvidenceCheckpoint>>,
    pub indicators_to_find: Option<Vec<String>>,
    pub decision_points: Option<Vec<DecisionPoint>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub prerequisites: Option<Vec<u32>>,
    pub notes: Option<String>,
}

/// Request to start a hunting session
#[derive(Debug, Clone, Deserialize)]
pub struct StartSessionRequest {
    pub playbook_id: String,
    pub scope: Option<String>,
    pub hypothesis: Option<String>,
}

/// Request to update session progress
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateSessionRequest {
    pub current_step: Option<u32>,
    pub status: Option<SessionStatus>,
    pub notes: Option<String>,
}

/// Request to update step progress
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateStepProgressRequest {
    pub status: StepStatus,
    pub query_results: Option<Vec<QueryResult>>,
    pub evidence_collected: Option<Vec<CollectedEvidence>>,
    pub notes: Option<String>,
}

/// Request to add a finding
#[derive(Debug, Clone, Deserialize)]
pub struct AddFindingRequest {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub step_number: u32,
    pub related_iocs: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub evidence: Option<Vec<CollectedEvidence>>,
    pub recommendations: Option<Vec<String>>,
}

/// Built-in playbooks library
pub struct BuiltinPlaybooks;

impl BuiltinPlaybooks {
    /// Get all built-in playbooks
    pub fn get_all() -> Vec<HuntingPlaybook> {
        vec![
            Self::credential_theft_playbook(),
            Self::lateral_movement_playbook(),
            Self::data_exfiltration_playbook(),
            Self::persistence_playbook(),
            Self::ransomware_playbook(),
            Self::command_and_control_playbook(),
            Self::initial_access_playbook(),
            Self::privilege_escalation_playbook(),
            Self::defense_evasion_playbook(),
            Self::insider_threat_playbook(),
            Self::living_off_the_land_playbook(),
        ]
    }

    /// Credential Theft Hunting Playbook
    pub fn credential_theft_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-credential-theft".to_string(),
            name: "Credential Theft Hunt".to_string(),
            description: "Hunt for credential theft and credential access techniques including LSASS access, credential dumping, and password spray attacks.".to_string(),
            category: PlaybookCategory::CredentialTheft,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "4-6 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "LSASS Process Access Analysis".to_string(),
                    description: "Identify suspicious access to the LSASS process which could indicate credential dumping attempts.".to_string(),
                    objective: "Detect potential Mimikatz or similar tool usage targeting LSASS memory.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=10 TargetImage="*lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1038", "0x1438") | stats count by SourceImage, SourceUser, ComputerName"#.to_string(),
                            description: "Detect processes accessing LSASS with suspicious access rights".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["SourceImage".to_string(), "SourceUser".to_string(), "ComputerName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Kusto,
                            query: r#"DeviceProcessEvents | where FileName =~ "lsass.exe" | where InitiatingProcessFileName !in~ ("svchost.exe", "csrss.exe", "wininit.exe") | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName"#.to_string(),
                            description: "KQL query for Microsoft Defender for Endpoint".to_string(),
                            data_sources: vec!["Microsoft Defender for Endpoint".to_string()],
                            expected_fields: vec!["DeviceName".to_string(), "InitiatingProcessFileName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "cp1-1".to_string(),
                            name: "Suspicious LSASS Access List".to_string(),
                            description: "Document all suspicious processes that accessed LSASS".to_string(),
                            evidence_types: vec!["query_results".to_string(), "screenshot".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Unknown processes accessing LSASS".to_string(),
                        "Access from PowerShell or cmd.exe to LSASS".to_string(),
                        "Access with 0x1010 or similar suspicious rights".to_string(),
                    ],
                    decision_points: vec![
                        DecisionPoint {
                            condition: "Suspicious LSASS access found".to_string(),
                            if_true: "Proceed to Step 2 for deeper analysis and check affected hosts".to_string(),
                            if_false: "Move to Step 3 to check for other credential theft techniques".to_string(),
                        },
                    ],
                    mitre_techniques: vec!["T1003.001".to_string()],
                    prerequisites: vec![],
                    notes: Some("Focus on processes that are not typical system processes like csrss.exe or wininit.exe".to_string()),
                },
                PlaybookStep {
                    step_number: 2,
                    title: "Credential Dumping Tool Detection".to_string(),
                    description: "Search for known credential dumping tools and their artifacts.".to_string(),
                    objective: "Identify presence of tools like Mimikatz, ProcDump, or credential dumping scripts.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows (CommandLine="*sekurlsa*" OR CommandLine="*kerberos::*" OR CommandLine="*lsadump*" OR CommandLine="*mimikatz*" OR CommandLine="*procdump*lsass*") | stats count by CommandLine, User, ComputerName"#.to_string(),
                            description: "Detect Mimikatz and ProcDump command-line usage".to_string(),
                            data_sources: vec!["Windows Security".to_string(), "Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "User".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "cp2-1".to_string(),
                            name: "Tool Detection Evidence".to_string(),
                            description: "Document any credential dumping tools detected".to_string(),
                            evidence_types: vec!["query_results".to_string(), "file_hash".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Mimikatz keywords in command lines".to_string(),
                        "ProcDump targeting LSASS".to_string(),
                        "comsvcs.dll MiniDump usage".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1003".to_string(), "T1003.001".to_string()],
                    prerequisites: vec![1],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Password Spray Detection".to_string(),
                    description: "Identify password spray attacks against domain accounts.".to_string(),
                    objective: "Detect patterns of authentication failures indicative of password spraying.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4625 | bucket _time span=1h | stats dc(TargetUserName) as unique_users count by _time, IpAddress | where unique_users > 10"#.to_string(),
                            description: "Detect many failed logins from single IP".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["IpAddress".to_string(), "unique_users".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Single IP with many failed authentications".to_string(),
                        "Multiple accounts targeted with same password".to_string(),
                        "Failed auth followed by success".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1110.003".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Kerberoasting Detection".to_string(),
                    description: "Hunt for Kerberoasting attacks targeting service account credentials.".to_string(),
                    objective: "Identify unusual TGS requests that may indicate Kerberoasting.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4769 TicketEncryptionType=0x17 | stats count by ServiceName, TargetUserName, IpAddress | where count > 5"#.to_string(),
                            description: "Detect RC4 TGS requests (potential Kerberoasting)".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["ServiceName".to_string(), "TargetUserName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "High volume of RC4 TGS requests".to_string(),
                        "Requests for multiple SPNs from single user".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1558.003".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["credentials".to_string(), "mimikatz".to_string(), "lsass".to_string()],
            mitre_tactics: vec![MitreTactic::CredentialAccess],
            mitre_techniques: vec!["T1003".to_string(), "T1110".to_string(), "T1558".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Lateral Movement Hunting Playbook
    pub fn lateral_movement_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-lateral-movement".to_string(),
            name: "Lateral Movement Hunt".to_string(),
            description: "Hunt for lateral movement techniques including RDP, SMB, WMI, and remote service usage.".to_string(),
            category: PlaybookCategory::LateralMovement,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "3-4 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "RDP Session Analysis".to_string(),
                    description: "Analyze RDP connections for suspicious lateral movement patterns.".to_string(),
                    objective: "Identify unusual RDP sessions between internal systems.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode IN (4624, 4625) LogonType=10 | stats count by SourceNetworkAddress, TargetUserName, ComputerName | where count > 3"#.to_string(),
                            description: "Track RDP logons across systems".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["SourceNetworkAddress".to_string(), "TargetUserName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Unusual source IPs for RDP".to_string(),
                        "RDP to servers from workstations".to_string(),
                        "After-hours RDP sessions".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1021.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "SMB Lateral Movement".to_string(),
                    description: "Detect lateral movement via SMB and admin shares.".to_string(),
                    objective: "Identify unauthorized access to admin shares (C$, ADMIN$).".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=5140 ShareName IN ("*C$", "*ADMIN$", "*IPC$") | stats count by SubjectUserName, IpAddress, ShareName"#.to_string(),
                            description: "Detect access to admin shares".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["SubjectUserName".to_string(), "IpAddress".to_string(), "ShareName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Non-admin users accessing admin shares".to_string(),
                        "Unusual systems accessing shares".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1021.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "WMI Remote Execution".to_string(),
                    description: "Hunt for remote code execution via WMI.".to_string(),
                    objective: "Detect WMIC or WMI-based lateral movement.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows (process_name="wmic.exe" OR process_name="wmiprvse.exe") CommandLine="*/node:*" | stats count by CommandLine, User, ComputerName"#.to_string(),
                            description: "Detect WMIC remote execution".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "ComputerName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "WMIC with /node parameter".to_string(),
                        "WMI process creation on remote systems".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1047".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "PsExec and Remote Service Creation".to_string(),
                    description: "Detect lateral movement via PsExec and remote service installation.".to_string(),
                    objective: "Identify unauthorized remote service creation.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=7045 ServiceName="PSEXE*" OR ServiceName="*-*-*-*-*" | stats count by ServiceName, ImagePath, ComputerName"#.to_string(),
                            description: "Detect PsExec service creation".to_string(),
                            data_sources: vec!["Windows System".to_string()],
                            expected_fields: vec!["ServiceName".to_string(), "ImagePath".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "PSEXESVC service creation".to_string(),
                        "Services with random GUIDs".to_string(),
                        "Services pointing to temp directories".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1569.002".to_string(), "T1021.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["lateral".to_string(), "rdp".to_string(), "smb".to_string(), "psexec".to_string()],
            mitre_tactics: vec![MitreTactic::LateralMovement],
            mitre_techniques: vec!["T1021".to_string(), "T1047".to_string(), "T1569".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Data Exfiltration Hunting Playbook
    pub fn data_exfiltration_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-data-exfiltration".to_string(),
            name: "Data Exfiltration Hunt".to_string(),
            description: "Hunt for data exfiltration attempts via various channels including DNS, HTTP, cloud storage, and encrypted channels.".to_string(),
            category: PlaybookCategory::DataExfiltration,
            difficulty: DifficultyLevel::Advanced,
            estimated_duration: "4-5 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Large Data Transfer Detection".to_string(),
                    description: "Identify unusually large outbound data transfers.".to_string(),
                    objective: "Detect potential bulk data exfiltration.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=network sourcetype=firewall direction=outbound | stats sum(bytes) as total_bytes by src_ip, dest_ip | where total_bytes > 100000000 | sort -total_bytes"#.to_string(),
                            description: "Find large outbound transfers".to_string(),
                            data_sources: vec!["Firewall".to_string(), "Network Flow".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "dest_ip".to_string(), "total_bytes".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Transfers over 100MB to external IPs".to_string(),
                        "After-hours large transfers".to_string(),
                        "Transfers to cloud storage services".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1041".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "DNS Tunneling Detection".to_string(),
                    description: "Hunt for DNS-based data exfiltration.".to_string(),
                    objective: "Identify DNS tunneling or unusual DNS query patterns.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=dns | eval query_len=len(query) | where query_len > 50 | stats count by src_ip, query | where count > 100"#.to_string(),
                            description: "Detect long DNS queries (potential tunneling)".to_string(),
                            data_sources: vec!["DNS".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "query".to_string(), "query_len".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Long subdomain queries".to_string(),
                        "High volume TXT queries".to_string(),
                        "Queries to suspicious domains".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1071.004".to_string(), "T1048.003".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Cloud Storage Exfiltration".to_string(),
                    description: "Detect uploads to cloud storage services.".to_string(),
                    objective: "Identify unauthorized uploads to cloud storage.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=proxy url IN ("*dropbox.com/upload*", "*drive.google.com/upload*", "*onedrive.live.com*", "*amazonaws.com*PUT*") | stats sum(bytes_out) by src_ip, url"#.to_string(),
                            description: "Track uploads to cloud storage".to_string(),
                            data_sources: vec!["Proxy".to_string(), "Web Gateway".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "url".to_string(), "bytes_out".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Large uploads to personal cloud storage".to_string(),
                        "Uploads from sensitive systems".to_string(),
                        "After-hours uploads".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1567".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["exfil".to_string(), "dns".to_string(), "cloud".to_string()],
            mitre_tactics: vec![MitreTactic::Exfiltration],
            mitre_techniques: vec!["T1041".to_string(), "T1048".to_string(), "T1567".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Persistence Hunting Playbook
    pub fn persistence_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-persistence".to_string(),
            name: "Persistence Mechanism Hunt".to_string(),
            description: "Hunt for persistence mechanisms including registry modifications, scheduled tasks, services, and startup items.".to_string(),
            category: PlaybookCategory::Persistence,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "3-4 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Registry Run Key Persistence".to_string(),
                    description: "Detect malicious entries in registry Run keys.".to_string(),
                    objective: "Identify unauthorized autostart entries.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=13 TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*" | stats count by TargetObject, Details, Image"#.to_string(),
                            description: "Track Run key modifications".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["TargetObject".to_string(), "Details".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Entries pointing to temp directories".to_string(),
                        "Encoded PowerShell commands".to_string(),
                        "Unknown executables".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1547.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "Scheduled Task Analysis".to_string(),
                    description: "Hunt for malicious scheduled tasks.".to_string(),
                    objective: "Identify suspicious scheduled tasks used for persistence.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4698 | stats count by TaskName, TaskContent | where match(TaskContent, "powershell|cmd|script|http")"#.to_string(),
                            description: "Detect suspicious scheduled task creation".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["TaskName".to_string(), "TaskContent".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Tasks with obfuscated names".to_string(),
                        "Tasks running PowerShell".to_string(),
                        "Tasks with network callbacks".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1053.005".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Service Installation Detection".to_string(),
                    description: "Detect malicious service installations.".to_string(),
                    objective: "Identify unauthorized services.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=7045 | stats count by ServiceName, ImagePath, ServiceType | where NOT match(ImagePath, "^C:\\Windows\\System32")"#.to_string(),
                            description: "Detect non-standard service installations".to_string(),
                            data_sources: vec!["Windows System".to_string()],
                            expected_fields: vec!["ServiceName".to_string(), "ImagePath".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Services in user directories".to_string(),
                        "Services with random names".to_string(),
                        "Services with suspicious paths".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1543.003".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["persistence".to_string(), "registry".to_string(), "scheduled_tasks".to_string()],
            mitre_tactics: vec![MitreTactic::Persistence],
            mitre_techniques: vec!["T1547".to_string(), "T1053".to_string(), "T1543".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Ransomware Hunting Playbook
    pub fn ransomware_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-ransomware".to_string(),
            name: "Ransomware Indicators Hunt".to_string(),
            description: "Hunt for ransomware indicators including mass file encryption, shadow copy deletion, and ransomware tooling.".to_string(),
            category: PlaybookCategory::Ransomware,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "2-3 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Shadow Copy Deletion Detection".to_string(),
                    description: "Detect attempts to delete Volume Shadow Copies.".to_string(),
                    objective: "Identify potential ransomware preparation activities.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*/set*recoveryenabled*No*") | stats count by CommandLine, User, ComputerName"#.to_string(),
                            description: "Detect shadow copy deletion".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "ComputerName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "vssadmin delete shadows".to_string(),
                        "WMIC shadowcopy delete".to_string(),
                        "bcdedit recovery disabled".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1490".to_string()],
                    prerequisites: vec![],
                    notes: Some("Shadow copy deletion is a strong indicator of ransomware".to_string()),
                },
                PlaybookStep {
                    step_number: 2,
                    title: "Mass File Modification Detection".to_string(),
                    description: "Detect rapid file modifications indicative of encryption.".to_string(),
                    objective: "Identify potential active encryption activity.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4663 ObjectType=File AccessMask=0x2 | bucket _time span=1m | stats count by _time, ProcessName | where count > 100"#.to_string(),
                            description: "Detect high-volume file modifications".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["ProcessName".to_string(), "count".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "High file modification rate".to_string(),
                        "New file extensions appearing".to_string(),
                        "Ransom note files created".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1486".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Known Ransomware Tools".to_string(),
                    description: "Search for known ransomware tools and artifacts.".to_string(),
                    objective: "Detect presence of known ransomware families.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows (FileName="*readme.txt" OR FileName="*DECRYPT*" OR FileName="*RANSOM*" OR FileName="*.encrypted" OR FileName="*.locked") | stats count by FileName, FilePath"#.to_string(),
                            description: "Detect ransomware artifacts".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["FileName".to_string(), "FilePath".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Ransom note files".to_string(),
                        "Encrypted file extensions".to_string(),
                        "Known ransomware executables".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1486".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["ransomware".to_string(), "encryption".to_string(), "vss".to_string()],
            mitre_tactics: vec![MitreTactic::Impact],
            mitre_techniques: vec!["T1486".to_string(), "T1490".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Command and Control (C2) Hunting Playbook
    pub fn command_and_control_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-c2".to_string(),
            name: "Command and Control Hunt".to_string(),
            description: "Hunt for C2 infrastructure including beaconing patterns, DNS-based C2, HTTP/HTTPS callbacks, and encrypted channels.".to_string(),
            category: PlaybookCategory::CommandAndControl,
            difficulty: DifficultyLevel::Advanced,
            estimated_duration: "4-6 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Beaconing Detection".to_string(),
                    description: "Identify periodic network callbacks characteristic of C2 beaconing.".to_string(),
                    objective: "Detect regular interval connections that may indicate C2 communication.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=network | bucket _time span=5m | stats count dc(dest_port) as ports by src_ip, dest_ip, _time | streamstats window=12 stdev(count) as std_count avg(count) as avg_count by src_ip, dest_ip | where std_count < 2 AND avg_count > 5"#.to_string(),
                            description: "Detect regular interval beaconing with low jitter".to_string(),
                            data_sources: vec!["Firewall".to_string(), "Network Flow".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "dest_ip".to_string(), "std_count".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Kusto,
                            query: r#"DeviceNetworkEvents | summarize ConnectionCount=count(), AvgTimeDiff=avg(datetime_diff('second', Timestamp, prev(Timestamp, 1))) by DeviceName, RemoteIP | where ConnectionCount > 50 and AvgTimeDiff between (55 .. 65)"#.to_string(),
                            description: "KQL for detecting ~60 second beacon intervals".to_string(),
                            data_sources: vec!["Microsoft Defender for Endpoint".to_string()],
                            expected_fields: vec!["DeviceName".to_string(), "RemoteIP".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "c2-cp1".to_string(),
                            name: "Beaconing Hosts".to_string(),
                            description: "List of hosts exhibiting beaconing behavior".to_string(),
                            evidence_types: vec!["query_results".to_string(), "timeline".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Regular interval connections".to_string(),
                        "Low jitter in connection timing".to_string(),
                        "Consistent packet sizes".to_string(),
                        "Connections to uncommon ports".to_string(),
                    ],
                    decision_points: vec![
                        DecisionPoint {
                            condition: "Beaconing pattern detected".to_string(),
                            if_true: "Investigate destination IP reputation and correlate with endpoint activity".to_string(),
                            if_false: "Continue to DNS C2 analysis".to_string(),
                        },
                    ],
                    mitre_techniques: vec!["T1071".to_string(), "T1095".to_string()],
                    prerequisites: vec![],
                    notes: Some("Cobalt Strike default beacon is 60 seconds, but attackers often modify this".to_string()),
                },
                PlaybookStep {
                    step_number: 2,
                    title: "DNS-Based C2 Detection".to_string(),
                    description: "Hunt for DNS-based command and control channels.".to_string(),
                    objective: "Identify DNS queries that may be carrying C2 traffic.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=dns | eval subdomain_len=len(mvindex(split(query,"."),0)) | where subdomain_len > 30 OR query_type="TXT" | stats count by src_ip, query | where count > 50"#.to_string(),
                            description: "Detect long subdomains or high-volume TXT queries".to_string(),
                            data_sources: vec!["DNS".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "query".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=dns | stats dc(query) as unique_queries count by src_ip | where unique_queries > 500 | sort -unique_queries"#.to_string(),
                            description: "Detect hosts with unusually high unique DNS queries".to_string(),
                            data_sources: vec!["DNS".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "unique_queries".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Base64-encoded subdomains".to_string(),
                        "High entropy in DNS queries".to_string(),
                        "TXT record queries to unusual domains".to_string(),
                        "NXDOMAIN responses with encoded data".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1071.004".to_string(), "T1568.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "HTTP/HTTPS C2 Analysis".to_string(),
                    description: "Analyze HTTP/HTTPS traffic for C2 indicators.".to_string(),
                    objective: "Identify suspicious web traffic patterns indicative of C2.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=proxy http_method=POST | stats count sum(bytes_out) as total_out by src_ip, dest_host, uri_path | where count > 100 AND total_out > 1000000"#.to_string(),
                            description: "Detect high-volume POST requests (potential data upload to C2)".to_string(),
                            data_sources: vec!["Proxy".to_string(), "Web Gateway".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "dest_host".to_string(), "uri_path".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=proxy user_agent="Mozilla*" | stats dc(user_agent) as ua_count count by src_ip | where ua_count = 1 AND count > 100"#.to_string(),
                            description: "Detect single user-agent with high request volume (potential C2 tool)".to_string(),
                            data_sources: vec!["Proxy".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "ua_count".to_string()],
                            suggested_timerange: Some("24h".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Unusual user-agent strings".to_string(),
                        "JA3/JA3S fingerprints matching known C2".to_string(),
                        "HTTP requests with encoded payloads".to_string(),
                        "Connections to dynamic DNS domains".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1071.001".to_string(), "T1573".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Known C2 Infrastructure Check".to_string(),
                    description: "Check against known C2 indicators and threat intelligence.".to_string(),
                    objective: "Identify connections to known malicious infrastructure.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=network [| inputlookup threat_intel_ips | rename ip as dest_ip] | stats count by src_ip, dest_ip, dest_port"#.to_string(),
                            description: "Match network traffic against threat intelligence".to_string(),
                            data_sources: vec!["Firewall".to_string(), "Threat Intel".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "dest_ip".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "c2-cp2".to_string(),
                            name: "C2 Infrastructure Matches".to_string(),
                            description: "Document any matches to known C2 infrastructure".to_string(),
                            evidence_types: vec!["query_results".to_string(), "ioc_report".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Connections to known C2 IPs".to_string(),
                        "DNS queries for known C2 domains".to_string(),
                        "JA3 fingerprints matching known malware".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1071".to_string()],
                    prerequisites: vec![],
                    notes: Some("Cross-reference with VirusTotal, AlienVault OTX, and internal threat intel".to_string()),
                },
            ],
            tags: vec!["c2".to_string(), "beaconing".to_string(), "cobaltstrike".to_string(), "dns".to_string()],
            mitre_tactics: vec![MitreTactic::CommandAndControl],
            mitre_techniques: vec!["T1071".to_string(), "T1095".to_string(), "T1568".to_string(), "T1573".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Initial Access Hunting Playbook
    pub fn initial_access_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-initial-access".to_string(),
            name: "Initial Access Hunt".to_string(),
            description: "Hunt for initial access vectors including phishing, exploitation of public-facing applications, and supply chain compromise.".to_string(),
            category: PlaybookCategory::InitialAccess,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "3-4 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Phishing Payload Detection".to_string(),
                    description: "Hunt for malicious email attachments and links.".to_string(),
                    objective: "Identify phishing campaigns targeting the organization.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=email (attachment_name="*.exe" OR attachment_name="*.js" OR attachment_name="*.vbs" OR attachment_name="*.hta" OR attachment_name="*.iso" OR attachment_name="*.img") | stats count by sender, subject, attachment_name"#.to_string(),
                            description: "Detect emails with executable attachments".to_string(),
                            data_sources: vec!["Email Gateway".to_string()],
                            expected_fields: vec!["sender".to_string(), "subject".to_string(), "attachment_name".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 (OriginalFileName="OUTLOOK.EXE" OR ParentImage="*outlook.exe") | stats count by Image, CommandLine, User"#.to_string(),
                            description: "Detect processes spawned from Outlook".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["Image".to_string(), "CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Executables delivered via email".to_string(),
                        "Macro-enabled Office documents".to_string(),
                        "ISO/IMG file attachments".to_string(),
                        "Links to credential harvesting sites".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1566.001".to_string(), "T1566.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "Office Macro Execution".to_string(),
                    description: "Detect malicious macro execution from Office applications.".to_string(),
                    objective: "Identify Office documents executing suspicious code.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 ParentImage IN ("*WINWORD.EXE", "*EXCEL.EXE", "*POWERPNT.EXE") Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*cscript.exe", "*mshta.exe") | stats count by ParentImage, Image, CommandLine, User"#.to_string(),
                            description: "Detect script interpreters spawned from Office".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["ParentImage".to_string(), "Image".to_string(), "CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "PowerShell spawned by Office apps".to_string(),
                        "WScript/CScript from Office".to_string(),
                        "Network connections from Office apps".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1204.002".to_string(), "T1059.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Public-Facing Application Exploitation".to_string(),
                    description: "Hunt for exploitation of web applications and services.".to_string(),
                    objective: "Identify successful exploitation of public-facing systems.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=webserver status=200 (uri_path="*../*" OR uri_path="*%2e%2e*" OR uri_query="*SELECT*FROM*" OR uri_query="*UNION*SELECT*" OR uri_query="*cmd=*" OR uri_query="*exec(*") | stats count by src_ip, uri_path, uri_query"#.to_string(),
                            description: "Detect path traversal and injection attempts".to_string(),
                            data_sources: vec!["Web Server".to_string(), "WAF".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "uri_path".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=webserver process_name="w3wp.exe" OR process_name="httpd" | where match(CommandLine, "powershell|cmd|whoami|net user") | stats count by src_ip, CommandLine"#.to_string(),
                            description: "Detect webshell command execution".to_string(),
                            data_sources: vec!["Web Server".to_string(), "Sysmon".to_string()],
                            expected_fields: vec!["src_ip".to_string(), "CommandLine".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Path traversal attempts".to_string(),
                        "SQL injection patterns".to_string(),
                        "Command injection in parameters".to_string(),
                        "Webshell indicators".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1190".to_string(), "T1505.003".to_string()],
                    prerequisites: vec![],
                    notes: Some("Focus on successful (HTTP 200) responses that may indicate exploitation".to_string()),
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Drive-by Download Detection".to_string(),
                    description: "Identify drive-by download attacks.".to_string(),
                    objective: "Detect browser-based exploitation and payload delivery.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 ParentImage IN ("*chrome.exe", "*firefox.exe", "*iexplore.exe", "*msedge.exe") Image IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*rundll32.exe", "*regsvr32.exe") | stats count by ParentImage, Image, CommandLine"#.to_string(),
                            description: "Detect suspicious processes spawned from browsers".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["ParentImage".to_string(), "Image".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Browser spawning interpreters".to_string(),
                        "Downloads from suspicious domains".to_string(),
                        "Exploit kit landing page patterns".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1189".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["phishing".to_string(), "macro".to_string(), "exploit".to_string(), "initial".to_string()],
            mitre_tactics: vec![MitreTactic::InitialAccess],
            mitre_techniques: vec!["T1566".to_string(), "T1190".to_string(), "T1189".to_string(), "T1204".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Privilege Escalation Hunting Playbook
    pub fn privilege_escalation_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-privesc".to_string(),
            name: "Privilege Escalation Hunt".to_string(),
            description: "Hunt for privilege escalation techniques including token manipulation, UAC bypass, and exploitation of vulnerable services.".to_string(),
            category: PlaybookCategory::PrivilegeEscalation,
            difficulty: DifficultyLevel::Advanced,
            estimated_duration: "3-4 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Token Manipulation Detection".to_string(),
                    description: "Detect token theft and manipulation attacks.".to_string(),
                    objective: "Identify processes manipulating access tokens.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4624 LogonType=9 | stats count by TargetUserName, TargetDomainName, IpAddress, ProcessName"#.to_string(),
                            description: "Detect NewCredentials logon (runas /netonly behavior)".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["TargetUserName".to_string(), "ProcessName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4648 | stats count by SubjectUserName, TargetUserName, ProcessName | where SubjectUserName != TargetUserName"#.to_string(),
                            description: "Detect explicit credential usage".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["SubjectUserName".to_string(), "TargetUserName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Token impersonation".to_string(),
                        "Primary token manipulation".to_string(),
                        "SID-History injection".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1134.001".to_string(), "T1134.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "UAC Bypass Detection".to_string(),
                    description: "Hunt for UAC bypass techniques.".to_string(),
                    objective: "Identify attempts to bypass User Account Control.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 (Image="*fodhelper.exe" OR Image="*eventvwr.exe" OR Image="*sdclt.exe" OR Image="*computerdefaults.exe") | stats count by ParentImage, Image, CommandLine"#.to_string(),
                            description: "Detect common UAC bypass binaries".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["ParentImage".to_string(), "Image".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=13 TargetObject="*\\ms-settings\\shell\\open\\command*" | stats count by Image, TargetObject, Details"#.to_string(),
                            description: "Detect fodhelper UAC bypass registry modification".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["Image".to_string(), "TargetObject".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Auto-elevating binaries abuse".to_string(),
                        "Environment variable hijacking".to_string(),
                        "DLL side-loading for elevation".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1548.002".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Vulnerable Service Exploitation".to_string(),
                    description: "Detect exploitation of vulnerable services for privilege escalation.".to_string(),
                    objective: "Identify service-based privilege escalation.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=7045 ServiceType="user mode service" | where NOT match(ImagePath, "(?i)^(C:\\Windows|C:\\Program Files)") | stats count by ServiceName, ImagePath"#.to_string(),
                            description: "Detect services created with non-standard paths".to_string(),
                            data_sources: vec!["Windows System".to_string()],
                            expected_fields: vec!["ServiceName".to_string(), "ImagePath".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4697 | stats count by ServiceName, ServiceFileName, SubjectUserName | where NOT match(SubjectUserName, "SYSTEM")"#.to_string(),
                            description: "Detect services installed by non-SYSTEM users".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["ServiceName".to_string(), "SubjectUserName".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Writable service binaries".to_string(),
                        "Unquoted service paths".to_string(),
                        "Weak service permissions".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1543.003".to_string(), "T1574.010".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Named Pipe Impersonation".to_string(),
                    description: "Detect named pipe impersonation attacks.".to_string(),
                    objective: "Identify attempts to escalate via named pipes.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=17 PipeName IN ("*\\pipe\\spoolss", "*\\pipe\\epmapper", "*\\pipe\\samr") | stats count by Image, PipeName, User"#.to_string(),
                            description: "Detect suspicious named pipe connections".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["Image".to_string(), "PipeName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "PrintSpoofer/PrintNightmare indicators".to_string(),
                        "JuicyPotato techniques".to_string(),
                        "Named pipe privilege escalation".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1134".to_string()],
                    prerequisites: vec![],
                    notes: Some("Focus on potato family exploits and print spooler abuse".to_string()),
                },
            ],
            tags: vec!["privesc".to_string(), "uac".to_string(), "token".to_string(), "potato".to_string()],
            mitre_tactics: vec![MitreTactic::PrivilegeEscalation],
            mitre_techniques: vec!["T1134".to_string(), "T1548".to_string(), "T1543".to_string(), "T1574".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Defense Evasion Hunting Playbook
    pub fn defense_evasion_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-defense-evasion".to_string(),
            name: "Defense Evasion Hunt".to_string(),
            description: "Hunt for defense evasion techniques including process injection, AMSI bypass, log tampering, and security tool disabling.".to_string(),
            category: PlaybookCategory::DefenseEvasion,
            difficulty: DifficultyLevel::Expert,
            estimated_duration: "4-5 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Process Injection Detection".to_string(),
                    description: "Detect various process injection techniques.".to_string(),
                    objective: "Identify code injection into legitimate processes.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=8 | where SourceImage != TargetImage | stats count by SourceImage, TargetImage, SourceUser | where NOT match(SourceImage, "(?i)csrss|services|lsass|svchost")"#.to_string(),
                            description: "Detect CreateRemoteThread injection".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["SourceImage".to_string(), "TargetImage".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=10 CallTrace="*UNKNOWN*" | stats count by SourceImage, TargetImage, GrantedAccess"#.to_string(),
                            description: "Detect process access with unknown call stacks".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["SourceImage".to_string(), "TargetImage".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "CreateRemoteThread to suspicious processes".to_string(),
                        "Hollowed processes".to_string(),
                        "DLL injection".to_string(),
                        "APC injection".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1055.001".to_string(), "T1055.002".to_string(), "T1055.012".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "AMSI/ETW Bypass Detection".to_string(),
                    description: "Detect attempts to bypass security monitoring.".to_string(),
                    objective: "Identify AMSI and ETW tampering.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 CommandLine="*AmsiScanBuffer*" OR CommandLine="*amsi.dll*" OR CommandLine="*AmsiInitFailed*" | stats count by CommandLine, User, Image"#.to_string(),
                            description: "Detect AMSI bypass attempts".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "Image".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 CommandLine="*EtwEventWrite*" OR CommandLine="*ntdll*NtTraceEvent*" | stats count by CommandLine, User"#.to_string(),
                            description: "Detect ETW bypass attempts".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "AmsiScanBuffer patching".to_string(),
                        "ETW provider disabling".to_string(),
                        ".NET assembly loading bypasses".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1562.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Log Tampering Detection".to_string(),
                    description: "Detect attempts to clear or tamper with logs.".to_string(),
                    objective: "Identify log clearing and tampering activities.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode IN (1102, 104) | stats count by ComputerName, SubjectUserName, Channel"#.to_string(),
                            description: "Detect security log clearing".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["ComputerName".to_string(), "SubjectUserName".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*wevtutil.exe" CommandLine="*cl*" OR Image="*powershell.exe" CommandLine="*Clear-EventLog*" | stats count by Image, CommandLine, User"#.to_string(),
                            description: "Detect event log clearing commands".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["Image".to_string(), "CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Security log cleared".to_string(),
                        "wevtutil clear-log usage".to_string(),
                        "Timestomping artifacts".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1070.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Security Tool Tampering".to_string(),
                    description: "Detect attempts to disable security tools.".to_string(),
                    objective: "Identify security product tampering.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows (EventCode=1 CommandLine="*Set-MpPreference*DisableRealtimeMonitoring*" OR CommandLine="*sc stop*" OR CommandLine="*net stop*") | where match(CommandLine, "(?i)defender|antivirus|security|firewall") | stats count by CommandLine, User"#.to_string(),
                            description: "Detect attempts to disable security software".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "User".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=7036 (Message="*Windows Defender*" OR Message="*Firewall*") Message="*stopped*" | stats count by Message, ComputerName"#.to_string(),
                            description: "Detect security service stops".to_string(),
                            data_sources: vec!["Windows System".to_string()],
                            expected_fields: vec!["Message".to_string(), "ComputerName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Defender disabled".to_string(),
                        "Firewall rules modified".to_string(),
                        "EDR tampering".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1562.001".to_string(), "T1562.004".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["evasion".to_string(), "injection".to_string(), "amsi".to_string(), "logs".to_string()],
            mitre_tactics: vec![MitreTactic::DefenseEvasion],
            mitre_techniques: vec!["T1055".to_string(), "T1562".to_string(), "T1070".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Insider Threat Hunting Playbook
    pub fn insider_threat_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-insider-threat".to_string(),
            name: "Insider Threat Hunt".to_string(),
            description: "Hunt for insider threat indicators including data hoarding, unusual access patterns, policy violations, and pre-departure behaviors.".to_string(),
            category: PlaybookCategory::InsiderThreat,
            difficulty: DifficultyLevel::Intermediate,
            estimated_duration: "4-5 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "Data Hoarding Detection".to_string(),
                    description: "Identify users accumulating large amounts of data.".to_string(),
                    objective: "Detect potential data theft preparation.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4663 AccessMask IN ("0x1", "0x20") | stats dc(ObjectName) as unique_files sum(eval(if(AccessMask="0x1",1,0))) as reads by SubjectUserName | where unique_files > 1000"#.to_string(),
                            description: "Detect users accessing unusually high number of files".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["SubjectUserName".to_string(), "unique_files".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=network sourcetype=dlp | stats sum(bytes) as total_bytes count by user, destination | where total_bytes > 500000000 | sort -total_bytes"#.to_string(),
                            description: "Detect large data transfers by user".to_string(),
                            data_sources: vec!["DLP".to_string()],
                            expected_fields: vec!["user".to_string(), "total_bytes".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "insider-cp1".to_string(),
                            name: "High Volume Users".to_string(),
                            description: "List of users with unusually high data access".to_string(),
                            evidence_types: vec!["query_results".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Mass file access".to_string(),
                        "USB device usage".to_string(),
                        "Cloud storage uploads".to_string(),
                        "Email attachments spike".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1074.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "After-Hours Activity Analysis".to_string(),
                    description: "Detect unusual after-hours system access.".to_string(),
                    objective: "Identify suspicious activity outside normal working hours.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4624 | eval hour=strftime(_time, "%H") | where hour < 6 OR hour > 22 | stats count by TargetUserName, ComputerName, hour | where count > 5"#.to_string(),
                            description: "Detect after-hours logons".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["TargetUserName".to_string(), "hour".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Late night access".to_string(),
                        "Weekend activity".to_string(),
                        "Holiday access".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1078".to_string()],
                    prerequisites: vec![],
                    notes: Some("Consider baseline for users with legitimate after-hours access".to_string()),
                },
                PlaybookStep {
                    step_number: 3,
                    title: "Unauthorized Access Attempts".to_string(),
                    description: "Detect access to systems or data outside normal scope.".to_string(),
                    objective: "Identify users accessing resources beyond their role.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=5145 | where ShareName != "IPC$" | stats dc(ShareName) as unique_shares count by SubjectUserName | where unique_shares > 10"#.to_string(),
                            description: "Detect users accessing many network shares".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["SubjectUserName".to_string(), "unique_shares".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4625 | stats count by TargetUserName, SubjectUserName, ComputerName | where count > 10 AND TargetUserName != SubjectUserName"#.to_string(),
                            description: "Detect failed access to other user accounts".to_string(),
                            data_sources: vec!["Windows Security".to_string()],
                            expected_fields: vec!["TargetUserName".to_string(), "SubjectUserName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Access to restricted shares".to_string(),
                        "Attempts to access other users' data".to_string(),
                        "Privilege abuse".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1083".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Resignation Risk Indicators".to_string(),
                    description: "Hunt for behaviors associated with departing employees.".to_string(),
                    objective: "Identify potential data theft by departing employees.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=proxy (url="*linkedin.com/jobs*" OR url="*indeed.com*" OR url="*glassdoor.com*") | stats count by src_ip, user | where count > 20"#.to_string(),
                            description: "Detect job searching activity".to_string(),
                            data_sources: vec!["Proxy".to_string()],
                            expected_fields: vec!["user".to_string(), "count".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=email recipient_domain!="internal.company.com" | where match(attachment_name, "(?i)resume|cv|portfolio") | stats count by sender, recipient_domain"#.to_string(),
                            description: "Detect resume/CV emails to external addresses".to_string(),
                            data_sources: vec!["Email Gateway".to_string()],
                            expected_fields: vec!["sender".to_string(), "recipient_domain".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Job search activity".to_string(),
                        "Resume sent externally".to_string(),
                        "Increased data access before departure".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1567".to_string()],
                    prerequisites: vec![],
                    notes: Some("Cross-reference with HR departure list for confirmed departures".to_string()),
                },
            ],
            tags: vec!["insider".to_string(), "data_theft".to_string(), "departing".to_string(), "dlp".to_string()],
            mitre_tactics: vec![MitreTactic::Collection, MitreTactic::Exfiltration],
            mitre_techniques: vec!["T1074".to_string(), "T1567".to_string(), "T1078".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }

    /// Living Off the Land (LOTL) Hunting Playbook
    pub fn living_off_the_land_playbook() -> HuntingPlaybook {
        HuntingPlaybook {
            id: "builtin-lotl".to_string(),
            name: "Living Off the Land Hunt".to_string(),
            description: "Hunt for abuse of legitimate system tools (LOLBins) including PowerShell, WMI, certutil, mshta, and other Windows utilities.".to_string(),
            category: PlaybookCategory::DefenseEvasion,
            difficulty: DifficultyLevel::Advanced,
            estimated_duration: "4-5 hours".to_string(),
            steps: vec![
                PlaybookStep {
                    step_number: 1,
                    title: "PowerShell Abuse Detection".to_string(),
                    description: "Hunt for malicious PowerShell usage.".to_string(),
                    objective: "Identify suspicious PowerShell commands and techniques.".to_string(),
                    expected_duration: Some("1h".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=4104 | where match(ScriptBlockText, "(?i)downloadstring|downloadfile|iex|invoke-expression|encodedcommand|-enc|-e |-ec |bypass|hidden|nop") | stats count by ScriptBlockText, ComputerName"#.to_string(),
                            description: "Detect suspicious PowerShell script blocks".to_string(),
                            data_sources: vec!["PowerShell".to_string()],
                            expected_fields: vec!["ScriptBlockText".to_string(), "ComputerName".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*powershell.exe" | where match(CommandLine, "(?i)-enc|-e |frombase64|gzipstream|decompress|memorys") | stats count by CommandLine, User, ParentImage"#.to_string(),
                            description: "Detect encoded/obfuscated PowerShell".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "ParentImage".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![
                        EvidenceCheckpoint {
                            id: "lotl-cp1".to_string(),
                            name: "Suspicious PowerShell".to_string(),
                            description: "Document suspicious PowerShell execution".to_string(),
                            evidence_types: vec!["query_results".to_string(), "script_content".to_string()],
                            required: true,
                        },
                    ],
                    indicators_to_find: vec![
                        "Encoded commands".to_string(),
                        "Download cradles".to_string(),
                        "Reflection-based loading".to_string(),
                        "AMSI bypass attempts".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1059.001".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 2,
                    title: "Certutil Abuse".to_string(),
                    description: "Detect abuse of certutil for downloading or encoding.".to_string(),
                    objective: "Identify certutil used as a download or encoding utility.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*certutil.exe" | where match(CommandLine, "(?i)-urlcache|-split|-encode|-decode|http") | stats count by CommandLine, User, ParentImage"#.to_string(),
                            description: "Detect certutil download/encode usage".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "User".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "URL download via certutil".to_string(),
                        "Base64 encoding/decoding".to_string(),
                        "Certificate abuse".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1140".to_string(), "T1105".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 3,
                    title: "MSHTA and HTA Abuse".to_string(),
                    description: "Detect malicious use of mshta.exe.".to_string(),
                    objective: "Identify mshta executing remote or local HTA files.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*mshta.exe" | where match(CommandLine, "(?i)http|javascript|vbscript") | stats count by CommandLine, User, ParentImage"#.to_string(),
                            description: "Detect mshta with remote or script content".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "ParentImage".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "MSHTA with inline scripts".to_string(),
                        "Remote HTA execution".to_string(),
                        "MSHTA spawning child processes".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1218.005".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 4,
                    title: "Rundll32 and Regsvr32 Abuse".to_string(),
                    description: "Detect proxy execution via rundll32 and regsvr32.".to_string(),
                    objective: "Identify malicious DLL loading via these utilities.".to_string(),
                    expected_duration: Some("45m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image IN ("*rundll32.exe", "*regsvr32.exe") | where match(CommandLine, "(?i)http|javascript|/s /n /u|scrobj") | stats count by Image, CommandLine, User"#.to_string(),
                            description: "Detect rundll32/regsvr32 proxy execution".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["Image".to_string(), "CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*regsvr32.exe" | where NOT match(CommandLine, "(?i)^C:\\Windows\\") | stats count by CommandLine, User, ParentImage"#.to_string(),
                            description: "Detect regsvr32 loading non-Windows DLLs".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "Rundll32 with URLs".to_string(),
                        "Regsvr32 /s /n /u flags".to_string(),
                        "COM scriptlet execution".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1218.010".to_string(), "T1218.011".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
                PlaybookStep {
                    step_number: 5,
                    title: "WMIC and BitsAdmin Abuse".to_string(),
                    description: "Detect abuse of WMIC and BitsAdmin.".to_string(),
                    objective: "Identify suspicious use of these utilities.".to_string(),
                    expected_duration: Some("30m".to_string()),
                    queries: vec![
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*wmic.exe" | where match(CommandLine, "(?i)process call create|format:|/node:") | stats count by CommandLine, User"#.to_string(),
                            description: "Detect WMIC process creation or format string abuse".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string(), "User".to_string()],
                            suggested_timerange: Some("7d".to_string()),
                        },
                        QueryTemplate {
                            query_type: QueryType::Splunk,
                            query: r#"index=windows EventCode=1 Image="*bitsadmin.exe" | where match(CommandLine, "(?i)/transfer|/addfile|http") | stats count by CommandLine, User"#.to_string(),
                            description: "Detect BitsAdmin downloads".to_string(),
                            data_sources: vec!["Sysmon".to_string()],
                            expected_fields: vec!["CommandLine".to_string()],
                            suggested_timerange: Some("30d".to_string()),
                        },
                    ],
                    evidence_checkpoints: vec![],
                    indicators_to_find: vec![
                        "WMIC process call create".to_string(),
                        "WMIC XSL execution".to_string(),
                        "BitsAdmin file transfers".to_string(),
                    ],
                    decision_points: vec![],
                    mitre_techniques: vec!["T1047".to_string(), "T1197".to_string(), "T1220".to_string()],
                    prerequisites: vec![],
                    notes: None,
                },
            ],
            tags: vec!["lolbin".to_string(), "powershell".to_string(), "certutil".to_string(), "wmic".to_string()],
            mitre_tactics: vec![MitreTactic::Execution, MitreTactic::DefenseEvasion],
            mitre_techniques: vec!["T1059".to_string(), "T1218".to_string(), "T1047".to_string(), "T1197".to_string()],
            is_builtin: true,
            user_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: "1.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_parsing() {
        assert_eq!(PlaybookCategory::from_str("credential_theft"), Some(PlaybookCategory::CredentialTheft));
        assert_eq!(PlaybookCategory::from_str("lateral_movement"), Some(PlaybookCategory::LateralMovement));
        assert_eq!(PlaybookCategory::from_str("exfil"), Some(PlaybookCategory::DataExfiltration));
    }

    #[test]
    fn test_builtin_playbooks() {
        let playbooks = BuiltinPlaybooks::get_all();
        assert_eq!(playbooks.len(), 5);

        let credential_playbook = &playbooks[0];
        assert_eq!(credential_playbook.category, PlaybookCategory::CredentialTheft);
        assert!(!credential_playbook.steps.is_empty());
    }

    #[test]
    fn test_playbook_structure() {
        let playbook = BuiltinPlaybooks::credential_theft_playbook();
        assert!(!playbook.steps.is_empty());
        assert!(!playbook.mitre_techniques.is_empty());

        for step in &playbook.steps {
            assert!(!step.title.is_empty());
            assert!(!step.description.is_empty());
        }
    }
}
