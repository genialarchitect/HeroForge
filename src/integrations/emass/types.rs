//! eMASS Types

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// eMASS connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassSettings {
    pub api_url: String,
    pub api_key: String,
    pub user_uid: String,
    pub certificate_path: Option<String>,
    pub certificate_password: Option<String>,
    pub timeout_seconds: u64,
}

impl Default for EmassSettings {
    fn default() -> Self {
        Self {
            api_url: "https://emass.apps.mil".to_string(),
            api_key: String::new(),
            user_uid: String::new(),
            certificate_path: None,
            certificate_password: None,
            timeout_seconds: 60,
        }
    }
}

/// eMASS System
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassSystem {
    pub system_id: i64,
    pub name: String,
    pub acronym: String,
    pub system_type: String,
    pub authorization_status: AuthorizationStatus,
    pub ato_date: Option<NaiveDate>,
    pub authorization_termination_date: Option<NaiveDate>,
    pub confidentiality: SecurityCategory,
    pub integrity: SecurityCategory,
    pub availability: SecurityCategory,
    pub description: Option<String>,
    pub owning_organization: Option<String>,
}

/// Authorization status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorizationStatus {
    NotYetAuthorized,
    AtoActive,
    AtoInherited,
    Iato,
    Dato,
    Unauthorized,
}

impl std::fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationStatus::NotYetAuthorized => write!(f, "Not Yet Authorized"),
            AuthorizationStatus::AtoActive => write!(f, "ATO Active"),
            AuthorizationStatus::AtoInherited => write!(f, "ATO Inherited"),
            AuthorizationStatus::Iato => write!(f, "IATO"),
            AuthorizationStatus::Dato => write!(f, "DATO"),
            AuthorizationStatus::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}

/// FIPS 199 security category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityCategory {
    Low,
    Moderate,
    High,
}

/// eMASS Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassControl {
    pub system_id: i64,
    pub control_acronym: String,
    pub cci: String,
    pub compliance_status: ControlComplianceStatus,
    pub implementation_status: ImplementationStatus,
    pub responsible_entities: Vec<String>,
    pub estimated_completion_date: Option<NaiveDate>,
    pub implementation_narrative: Option<String>,
    pub slcm_criticality: Option<String>,
    pub slcm_frequency: Option<String>,
}

/// Control compliance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlComplianceStatus {
    Compliant,
    NonCompliant,
    NotApplicable,
    Other,
}

/// Implementation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    Implemented,
    PartiallyImplemented,
    PlannedNotImplemented,
    NotApplicable,
    NotProvided,
}

/// eMASS POA&M (Plan of Action & Milestones)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassPoam {
    pub poam_id: Option<i64>,
    pub system_id: i64,
    pub control_acronym: String,
    pub cci: Option<String>,
    pub status: PoamStatus,
    pub weakness_description: String,
    pub source_identified: String,
    pub severity: PoamSeverity,
    pub scheduled_completion_date: NaiveDate,
    pub milestone_changes: Vec<PoamMilestone>,
    pub resources_required: Option<String>,
    pub comments: Option<String>,
    pub created_date: Option<DateTime<Utc>>,
    pub modified_date: Option<DateTime<Utc>>,
}

/// POA&M status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoamStatus {
    Ongoing,
    Delayed,
    Completed,
    Cancelled,
    RiskAccepted,
}

/// POA&M severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoamSeverity {
    VeryLow,
    Low,
    Moderate,
    High,
    VeryHigh,
}

/// POA&M milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoamMilestone {
    pub milestone_id: Option<i64>,
    pub description: String,
    pub scheduled_completion_date: NaiveDate,
    pub status: MilestoneStatus,
}

/// Milestone status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MilestoneStatus {
    Pending,
    InProgress,
    Completed,
    Delayed,
}

/// eMASS Artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmassArtifact {
    pub artifact_id: Option<i64>,
    pub system_id: i64,
    pub filename: String,
    pub artifact_type: ArtifactType,
    pub category: ArtifactCategory,
    pub upload_date: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

/// Artifact type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    ScanResult,
    PolicyDocument,
    Procedure,
    TestResults,
    TrainingRecord,
    Evidence,
    Other,
}

/// Artifact category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    ImplementationGuidance,
    SupportingArtifacts,
    TestEvidence,
    AssessmentObjective,
}
