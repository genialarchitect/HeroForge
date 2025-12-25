//! Purple Team types for attack execution and detection validation

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a purple team exercise
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ExerciseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExerciseStatus::Pending => write!(f, "pending"),
            ExerciseStatus::Running => write!(f, "running"),
            ExerciseStatus::Completed => write!(f, "completed"),
            ExerciseStatus::Failed => write!(f, "failed"),
            ExerciseStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Status of an individual attack execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStatus {
    Executed,
    Blocked,
    Failed,
    Skipped,
}

/// Detection status for an attack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Detected,
    PartiallyDetected,
    NotDetected,
    Pending,
}

/// Severity of a detection gap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for GapSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GapSeverity::Critical => write!(f, "critical"),
            GapSeverity::High => write!(f, "high"),
            GapSeverity::Medium => write!(f, "medium"),
            GapSeverity::Low => write!(f, "low"),
        }
    }
}

/// Type of detection recommendation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationType {
    NewRule,
    RuleTuning,
    DataSource,
    LogEnhancement,
    Integration,
}

/// MITRE ATT&CK Tactic
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

    pub fn name(&self) -> &'static str {
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
}

impl std::fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// MITRE ATT&CK Technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,           // e.g., T1003 or T1003.001
    pub name: String,
    pub tactic: MitreTactic,
    pub description: String,
    pub data_sources: Vec<String>,
    pub is_subtechnique: bool,
    pub parent_id: Option<String>,
}

/// Purple Team Exercise configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamExercise {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub siem_integration_id: Option<String>,
    pub attack_configs: Vec<PurpleAttackConfig>,
    pub detection_timeout_secs: u64,
    pub status: ExerciseStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Configuration for a single attack in an exercise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleAttackConfig {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: MitreTactic,
    pub attack_type: String,     // Maps to HeroForge attack types
    pub target: String,
    pub parameters: HashMap<String, String>,
    pub enabled: bool,
}

/// Result of executing an attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleAttackResult {
    pub id: String,
    pub exercise_id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: MitreTactic,
    pub attack_type: String,
    pub target: String,
    pub attack_status: AttackStatus,
    pub detection_status: DetectionStatus,
    pub detection_details: Option<DetectionDetails>,
    pub time_to_detect_ms: Option<i64>,
    pub executed_at: DateTime<Utc>,
    pub error_message: Option<String>,
}

/// Details about detection from SIEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionDetails {
    pub alerts_matched: Vec<MatchedAlert>,
    pub log_sources: Vec<String>,
    pub detection_time: Option<DateTime<Utc>>,
    pub confidence: f32,
}

/// Alert matched from SIEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedAlert {
    pub alert_id: String,
    pub rule_name: String,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

/// Detection coverage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCoverage {
    pub id: String,
    pub exercise_id: String,
    pub by_tactic: HashMap<String, TacticCoverage>,
    pub by_technique: HashMap<String, TechniqueCoverage>,
    pub overall_score: f32,
    pub calculated_at: DateTime<Utc>,
}

/// Coverage metrics for a tactic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub total_techniques: usize,
    pub detected: usize,
    pub partially_detected: usize,
    pub not_detected: usize,
    pub coverage_percent: f32,
}

/// Coverage metrics for a technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub tests_run: usize,
    pub detected: usize,
    pub partially_detected: usize,
    pub not_detected: usize,
    pub coverage_percent: f32,
    pub avg_time_to_detect_ms: Option<i64>,
}

/// Detection gap identified during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionGap {
    pub id: String,
    pub exercise_id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: MitreTactic,
    pub severity: GapSeverity,
    pub recommendations: Vec<DetectionRecommendation>,
    pub status: GapStatus,
    pub created_at: DateTime<Utc>,
    pub remediated_at: Option<DateTime<Utc>>,
}

/// Status of a detection gap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapStatus {
    Open,
    InProgress,
    Remediated,
    Accepted,
}

impl std::fmt::Display for GapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GapStatus::Open => write!(f, "open"),
            GapStatus::InProgress => write!(f, "in_progress"),
            GapStatus::Remediated => write!(f, "remediated"),
            GapStatus::Accepted => write!(f, "accepted"),
        }
    }
}

/// Recommendation to improve detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecommendation {
    pub recommendation_type: RecommendationType,
    pub title: String,
    pub description: String,
    pub sigma_rule: Option<String>,
    pub splunk_query: Option<String>,
    pub elastic_query: Option<String>,
    pub data_sources_required: Vec<String>,
    pub priority: u8,  // 1-5, 1 being highest
}

/// Request to create a new exercise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExerciseRequest {
    pub name: String,
    pub description: Option<String>,
    pub siem_integration_id: Option<String>,
    pub attack_configs: Vec<PurpleAttackConfig>,
    pub detection_timeout_secs: Option<u64>,
}

/// Request to start an exercise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartExerciseRequest {
    pub skip_techniques: Option<Vec<String>>,
}

/// Request to update gap status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGapStatusRequest {
    pub status: GapStatus,
    pub notes: Option<String>,
}

/// Purple Team dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamDashboard {
    pub total_exercises: usize,
    pub completed_exercises: usize,
    pub total_attacks_run: usize,
    pub detection_rate: f32,
    pub avg_time_to_detect_ms: i64,
    pub open_gaps: usize,
    pub critical_gaps: usize,
    pub coverage_by_tactic: Vec<TacticCoverage>,
    pub recent_exercises: Vec<ExerciseSummary>,
}

/// Summary of an exercise for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseSummary {
    pub id: String,
    pub name: String,
    pub status: ExerciseStatus,
    pub attacks_run: usize,
    pub detection_rate: f32,
    pub gaps_found: usize,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// ATT&CK Matrix cell for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixCell {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub tested: bool,
    pub detection_status: Option<DetectionStatus>,
    pub coverage_percent: f32,
    pub gap_severity: Option<GapSeverity>,
}

/// Full ATT&CK Matrix for UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMatrix {
    pub tactics: Vec<String>,
    pub cells: HashMap<String, Vec<MatrixCell>>,  // tactic -> cells
    pub overall_coverage: f32,
    pub tested_techniques: usize,
    pub total_techniques: usize,
}
