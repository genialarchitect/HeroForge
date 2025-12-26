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

// ============================================================================
// Phase 5 Purple Team Enhancement Types
// ============================================================================

/// Method of attack execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMethod {
    Manual,
    AtomicRedTeam,
    Caldera,
    C2Framework,
    Custom,
}

impl std::fmt::Display for ExecutionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionMethod::Manual => write!(f, "manual"),
            ExecutionMethod::AtomicRedTeam => write!(f, "atomic_red_team"),
            ExecutionMethod::Caldera => write!(f, "caldera"),
            ExecutionMethod::C2Framework => write!(f, "c2_framework"),
            ExecutionMethod::Custom => write!(f, "custom"),
        }
    }
}

/// Status of an attack execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionStatus::Pending => write!(f, "pending"),
            ExecutionStatus::Running => write!(f, "running"),
            ExecutionStatus::Completed => write!(f, "completed"),
            ExecutionStatus::Failed => write!(f, "failed"),
            ExecutionStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Attack execution record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackExecution {
    pub id: String,
    pub exercise_id: Option<String>,
    pub technique_id: String,
    pub execution_method: ExecutionMethod,
    pub execution_config: serde_json::Value,
    pub c2_session_id: Option<String>,
    pub status: ExecutionStatus,
    pub output: Option<String>,
    pub artifacts: Vec<ExecutionArtifact>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Artifact created during attack execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionArtifact {
    pub artifact_type: String, // 'file', 'process', 'registry', 'network'
    pub path: Option<String>,
    pub hash: Option<String>,
    pub description: String,
}

/// Type of SIEM connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiemType {
    Splunk,
    Elasticsearch,
    MicrosoftSentinel,
    QRadar,
    CrowdStrike,
    Other,
}

impl std::fmt::Display for SiemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiemType::Splunk => write!(f, "splunk"),
            SiemType::Elasticsearch => write!(f, "elasticsearch"),
            SiemType::MicrosoftSentinel => write!(f, "microsoft_sentinel"),
            SiemType::QRadar => write!(f, "qradar"),
            SiemType::CrowdStrike => write!(f, "crowdstrike"),
            SiemType::Other => write!(f, "other"),
        }
    }
}

/// SIEM connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Error,
    Unknown,
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionStatus::Connected => write!(f, "connected"),
            ConnectionStatus::Disconnected => write!(f, "disconnected"),
            ConnectionStatus::Error => write!(f, "error"),
            ConnectionStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// SIEM connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConnection {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub siem_type: SiemType,
    pub connection_config: serde_json::Value, // Encrypted in DB
    pub is_active: bool,
    pub last_test_at: Option<DateTime<Utc>>,
    pub last_test_status: Option<ConnectionStatus>,
    pub created_at: DateTime<Utc>,
}

/// Detection check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCheck {
    pub id: String,
    pub execution_id: String,
    pub siem_connection_id: String,
    pub technique_id: String,
    pub check_query: String,
    pub expected_alert_type: Option<String>,
    pub status: DetectionCheckStatus,
    pub alert_found: bool,
    pub alert_details: Option<serde_json::Value>,
    pub time_to_detect_seconds: Option<i32>,
    pub checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Status of detection check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionCheckStatus {
    Pending,
    Detected,
    Missed,
    Partial,
}

impl std::fmt::Display for DetectionCheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionCheckStatus::Pending => write!(f, "pending"),
            DetectionCheckStatus::Detected => write!(f, "detected"),
            DetectionCheckStatus::Missed => write!(f, "missed"),
            DetectionCheckStatus::Partial => write!(f, "partial"),
        }
    }
}

/// Threat actor motivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatMotivation {
    Espionage,
    Financial,
    Destruction,
    Hacktivism,
    Unknown,
}

impl std::fmt::Display for ThreatMotivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatMotivation::Espionage => write!(f, "espionage"),
            ThreatMotivation::Financial => write!(f, "financial"),
            ThreatMotivation::Destruction => write!(f, "destruction"),
            ThreatMotivation::Hacktivism => write!(f, "hacktivism"),
            ThreatMotivation::Unknown => write!(f, "unknown"),
        }
    }
}

/// Adversary emulation profile (APT simulation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdversaryProfile {
    pub id: String,
    pub name: String, // APT29, FIN7, Lazarus, etc.
    pub description: String,
    pub motivation: ThreatMotivation,
    pub target_sectors: Vec<String>,
    pub techniques: Vec<String>,
    pub ttp_chains: Vec<TtpChain>,
    pub tools_used: Vec<String>,
    pub references: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Chain of TTPs for emulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtpChain {
    pub name: String,
    pub description: String,
    pub techniques: Vec<ChainedTechnique>,
}

/// Technique in a TTP chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedTechnique {
    pub technique_id: String,
    pub order: u32,
    pub depends_on: Option<String>,
    pub delay_seconds: Option<u32>,
}

/// Emulation campaign status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Ready,
    Running,
    Paused,
    Completed,
    Failed,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignStatus::Draft => write!(f, "draft"),
            CampaignStatus::Ready => write!(f, "ready"),
            CampaignStatus::Running => write!(f, "running"),
            CampaignStatus::Paused => write!(f, "paused"),
            CampaignStatus::Completed => write!(f, "completed"),
            CampaignStatus::Failed => write!(f, "failed"),
        }
    }
}

/// Adversary emulation campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationCampaign {
    pub id: String,
    pub user_id: String,
    pub profile_id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: CampaignStatus,
    pub phases: serde_json::Value, // Campaign phases
    pub current_phase: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Type of detection rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionRuleType {
    Sigma,
    SplunkSpl,
    ElasticKql,
    ElasticEql,
    Yara,
    Snort,
}

impl std::fmt::Display for DetectionRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionRuleType::Sigma => write!(f, "sigma"),
            DetectionRuleType::SplunkSpl => write!(f, "splunk_spl"),
            DetectionRuleType::ElasticKql => write!(f, "elastic_kql"),
            DetectionRuleType::ElasticEql => write!(f, "elastic_eql"),
            DetectionRuleType::Yara => write!(f, "yara"),
            DetectionRuleType::Snort => write!(f, "snort"),
        }
    }
}

/// Validation status for generated detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Untested,
    Testing,
    Validated,
    InvalidSyntax,
    LowEffectiveness,
    HighFalsePositives,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Untested => write!(f, "untested"),
            ValidationStatus::Testing => write!(f, "testing"),
            ValidationStatus::Validated => write!(f, "validated"),
            ValidationStatus::InvalidSyntax => write!(f, "invalid_syntax"),
            ValidationStatus::LowEffectiveness => write!(f, "low_effectiveness"),
            ValidationStatus::HighFalsePositives => write!(f, "high_false_positives"),
        }
    }
}

/// Generated detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedDetection {
    pub id: String,
    pub user_id: String,
    pub technique_id: String,
    pub detection_type: DetectionRuleType,
    pub rule_content: String,
    pub rule_metadata: Option<serde_json::Value>,
    pub generation_source: String, // 'manual', 'attack_output', 'ai_generated'
    pub execution_id: Option<String>,
    pub validation_status: ValidationStatus,
    pub false_positive_rate: Option<f64>,
    pub created_at: DateTime<Utc>,
}

/// Control validation result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationResult {
    Effective,
    PartiallyEffective,
    Ineffective,
    NotTested,
}

impl std::fmt::Display for ValidationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationResult::Effective => write!(f, "effective"),
            ValidationResult::PartiallyEffective => write!(f, "partially_effective"),
            ValidationResult::Ineffective => write!(f, "ineffective"),
            ValidationResult::NotTested => write!(f, "not_tested"),
        }
    }
}

/// Control validation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlValidation {
    pub id: String,
    pub user_id: String,
    pub control_id: String,
    pub technique_id: String,
    pub validation_type: String, // 'automated', 'manual'
    pub status: String,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub executed_at: Option<DateTime<Utc>>,
    pub result: Option<ValidationResult>,
    pub evidence_refs: Option<serde_json::Value>,
    pub notes: Option<String>,
    pub validated_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Validation schedule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSchedule {
    pub id: String,
    pub user_id: String,
    pub control_id: String,
    pub technique_ids: Vec<String>,
    pub frequency: String, // 'weekly', 'monthly', 'quarterly'
    pub next_run_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Purple Team enhanced dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamEnhancedDashboard {
    pub total_exercises: i32,
    pub completed_exercises: i32,
    pub total_attacks_run: i32,
    pub detection_rate: f64,
    pub avg_time_to_detect_seconds: i32,
    pub open_gaps: i32,
    pub critical_gaps: i32,
    pub coverage_by_tactic: Vec<TacticCoverage>,
    pub recent_exercises: Vec<ExerciseSummary>,
    // Enhanced metrics
    pub active_campaigns: i32,
    pub generated_detections: i32,
    pub validated_controls: i32,
    pub siem_connections: i32,
    pub adversary_profiles: i32,
}

/// Request to create an attack execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateExecutionRequest {
    pub exercise_id: Option<String>,
    pub technique_id: String,
    pub execution_method: ExecutionMethod,
    pub execution_config: serde_json::Value,
    pub c2_session_id: Option<String>,
}

/// Request to create SIEM connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSiemConnectionRequest {
    pub name: String,
    pub siem_type: SiemType,
    pub connection_config: serde_json::Value,
}

/// Request to create emulation campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub profile_id: String,
    pub name: String,
    pub description: Option<String>,
    pub phases: serde_json::Value,
}

/// Request to generate detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateDetectionRequest {
    pub technique_id: String,
    pub detection_type: DetectionRuleType,
    pub execution_id: Option<String>,
    pub custom_indicators: Option<Vec<String>>,
}

/// Request to create control validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateValidationRequest {
    pub control_id: String,
    pub technique_id: String,
    pub validation_type: String,
    pub scheduled_at: Option<DateTime<Utc>>,
}

/// Request to create validation schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScheduleRequest {
    pub control_id: String,
    pub technique_ids: Vec<String>,
    pub frequency: String,
}
