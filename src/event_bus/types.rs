//! Event Bus Types
//!
//! Defines all event types that can be published across teams.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Security events that can be published across teams
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SecurityEvent {
    // Red Team Events
    VulnerabilityDiscovered(VulnerabilityEvent),
    ScanCompleted(ScanEvent),
    ExploitSuccessful(ExploitEvent),
    AssetDiscovered(AssetEvent),

    // Blue Team Events
    DetectionRuleCreated(DetectionRuleEvent),
    AlertTriggered(AlertEvent),
    ThreatDetected(ThreatEvent),

    // Purple Team Events
    ExerciseCompleted(ExerciseEvent),
    GapIdentified(GapEvent),
    DetectionValidated(ValidationEvent),
    AttackSimulated(AttackSimulationEvent),

    // Yellow Team Events
    CodeVulnerabilityFound(CodeVulnEvent),
    DependencyRiskDetected(DependencyEvent),
    SecureCodeScanned(CodeScanEvent),
    BuildFailed(BuildFailureEvent),

    // Orange Team Events
    PhishingClicked(PhishingEvent),
    TrainingCompleted(TrainingEvent),
    UserRiskChanged(UserRiskEvent),
    SecurityAwarenessTest(AwarenessTestEvent),

    // White Team Events
    ComplianceViolation(ComplianceEvent),
    PolicyUpdated(PolicyEvent),
    RiskAssessed(RiskAssessmentEvent),
    AuditCompleted(AuditEvent),

    // Green Team Events (SOC)
    IncidentCreated(IncidentEvent),
    IncidentResolved(IncidentEvent),
    PlaybookExecuted(PlaybookEvent),
    SoarAutomated(SoarEvent),
}

impl SecurityEvent {
    /// Get the event type as a string
    pub fn event_type(&self) -> &str {
        match self {
            SecurityEvent::VulnerabilityDiscovered(_) => "VulnerabilityDiscovered",
            SecurityEvent::ScanCompleted(_) => "ScanCompleted",
            SecurityEvent::ExploitSuccessful(_) => "ExploitSuccessful",
            SecurityEvent::AssetDiscovered(_) => "AssetDiscovered",
            SecurityEvent::DetectionRuleCreated(_) => "DetectionRuleCreated",
            SecurityEvent::AlertTriggered(_) => "AlertTriggered",
            SecurityEvent::ThreatDetected(_) => "ThreatDetected",
            SecurityEvent::ExerciseCompleted(_) => "ExerciseCompleted",
            SecurityEvent::GapIdentified(_) => "GapIdentified",
            SecurityEvent::DetectionValidated(_) => "DetectionValidated",
            SecurityEvent::AttackSimulated(_) => "AttackSimulated",
            SecurityEvent::CodeVulnerabilityFound(_) => "CodeVulnerabilityFound",
            SecurityEvent::DependencyRiskDetected(_) => "DependencyRiskDetected",
            SecurityEvent::SecureCodeScanned(_) => "SecureCodeScanned",
            SecurityEvent::BuildFailed(_) => "BuildFailed",
            SecurityEvent::PhishingClicked(_) => "PhishingClicked",
            SecurityEvent::TrainingCompleted(_) => "TrainingCompleted",
            SecurityEvent::UserRiskChanged(_) => "UserRiskChanged",
            SecurityEvent::SecurityAwarenessTest(_) => "SecurityAwarenessTest",
            SecurityEvent::ComplianceViolation(_) => "ComplianceViolation",
            SecurityEvent::PolicyUpdated(_) => "PolicyUpdated",
            SecurityEvent::RiskAssessed(_) => "RiskAssessmentEvent",
            SecurityEvent::AuditCompleted(_) => "AuditCompleted",
            SecurityEvent::IncidentCreated(_) => "IncidentCreated",
            SecurityEvent::IncidentResolved(_) => "IncidentResolved",
            SecurityEvent::PlaybookExecuted(_) => "PlaybookExecuted",
            SecurityEvent::SoarAutomated(_) => "SoarAutomated",
        }
    }

    /// Get the source team
    pub fn source_team(&self) -> &str {
        match self {
            SecurityEvent::VulnerabilityDiscovered(_)
            | SecurityEvent::ScanCompleted(_)
            | SecurityEvent::ExploitSuccessful(_)
            | SecurityEvent::AssetDiscovered(_) => "red",
            SecurityEvent::DetectionRuleCreated(_)
            | SecurityEvent::AlertTriggered(_)
            | SecurityEvent::ThreatDetected(_) => "blue",
            SecurityEvent::ExerciseCompleted(_)
            | SecurityEvent::GapIdentified(_)
            | SecurityEvent::DetectionValidated(_)
            | SecurityEvent::AttackSimulated(_) => "purple",
            SecurityEvent::CodeVulnerabilityFound(_)
            | SecurityEvent::DependencyRiskDetected(_)
            | SecurityEvent::SecureCodeScanned(_)
            | SecurityEvent::BuildFailed(_) => "yellow",
            SecurityEvent::PhishingClicked(_)
            | SecurityEvent::TrainingCompleted(_)
            | SecurityEvent::UserRiskChanged(_)
            | SecurityEvent::SecurityAwarenessTest(_) => "orange",
            SecurityEvent::ComplianceViolation(_)
            | SecurityEvent::PolicyUpdated(_)
            | SecurityEvent::RiskAssessed(_)
            | SecurityEvent::AuditCompleted(_) => "white",
            SecurityEvent::IncidentCreated(_)
            | SecurityEvent::IncidentResolved(_)
            | SecurityEvent::PlaybookExecuted(_)
            | SecurityEvent::SoarAutomated(_) => "green",
        }
    }
}

// ============================================================================
// Red Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityEvent {
    pub vulnerability_id: String,
    pub asset_id: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub cve_id: Option<String>,
    pub description: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub scan_id: String,
    pub user_id: String,
    pub targets: Vec<String>,
    pub vulnerability_count: usize,
    pub host_count: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitEvent {
    pub exploit_id: String,
    pub vulnerability_id: String,
    pub asset_id: String,
    pub technique: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEvent {
    pub asset_id: String,
    pub asset_type: String,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Blue Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleEvent {
    pub rule_id: String,
    pub rule_type: String, // sigma, splunk, elastic, yara
    pub name: String,
    pub mitre_techniques: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub alert_id: String,
    pub rule_id: String,
    pub severity: String,
    pub asset_id: Option<String>,
    pub user_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub threat_id: String,
    pub threat_type: String,
    pub indicators: Vec<String>,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Purple Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseEvent {
    pub exercise_id: String,
    pub name: String,
    pub attacks_executed: usize,
    pub detections_validated: usize,
    pub gaps_found: usize,
    pub coverage_score: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapEvent {
    pub gap_id: String,
    pub exercise_id: String,
    pub mitre_technique: String,
    pub severity: String,
    pub asset_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub validation_id: String,
    pub rule_id: String,
    pub attack_technique: String,
    pub detected: bool,
    pub time_to_detect: Option<u64>, // milliseconds
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSimulationEvent {
    pub simulation_id: String,
    pub technique: String,
    pub asset_id: String,
    pub success: bool,
    pub detected: bool,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Yellow Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeVulnEvent {
    pub finding_id: String,
    pub repository: String,
    pub file_path: String,
    pub vulnerability_type: String,
    pub severity: String,
    pub developer_id: String,
    pub cwe_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEvent {
    pub dependency_id: String,
    pub package_name: String,
    pub version: String,
    pub vulnerability_count: usize,
    pub risk_level: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeScanEvent {
    pub scan_id: String,
    pub repository: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildFailureEvent {
    pub build_id: String,
    pub repository: String,
    pub failure_reason: String,
    pub security_related: bool,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Orange Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingEvent {
    pub campaign_id: String,
    pub user_id: String,
    pub email_template_id: String,
    pub clicked: bool,
    pub credentials_entered: bool,
    pub reported: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingEvent {
    pub training_id: String,
    pub user_id: String,
    pub course_id: String,
    pub completed: bool,
    pub score: Option<f64>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRiskEvent {
    pub user_id: String,
    pub previous_score: f64,
    pub new_score: f64,
    pub risk_level: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwarenessTestEvent {
    pub test_id: String,
    pub user_id: String,
    pub test_type: String,
    pub passed: bool,
    pub score: f64,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// White Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub violation_id: String,
    pub framework: String,
    pub control_id: String,
    pub severity: String,
    pub asset_id: Option<String>,
    pub user_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    pub policy_id: String,
    pub policy_name: String,
    pub action: String, // created, updated, deleted
    pub affected_users: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentEvent {
    pub assessment_id: String,
    pub asset_id: Option<String>,
    pub risk_score: f64,
    pub risk_level: String,
    pub mitigations_required: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: String,
    pub audit_type: String,
    pub findings_count: usize,
    pub compliance_score: f64,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Green Team Events
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub incident_id: String,
    pub severity: String,
    pub incident_type: String,
    pub affected_assets: Vec<String>,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookEvent {
    pub playbook_id: String,
    pub incident_id: Option<String>,
    pub actions_executed: usize,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarEvent {
    pub automation_id: String,
    pub trigger_event: String,
    pub actions: Vec<String>,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
}
