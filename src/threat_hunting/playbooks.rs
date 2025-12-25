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
