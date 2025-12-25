//! Core types for the Digital Forensics module

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// =============================================================================
// Case Management Types
// =============================================================================

/// Forensic case types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseType {
    IncidentResponse,
    MalwareAnalysis,
    DataBreach,
    InsiderThreat,
    NetworkIntrusion,
    RansomwareRecovery,
    Litigation,
    Other,
}

impl CaseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaseType::IncidentResponse => "incident_response",
            CaseType::MalwareAnalysis => "malware_analysis",
            CaseType::DataBreach => "data_breach",
            CaseType::InsiderThreat => "insider_threat",
            CaseType::NetworkIntrusion => "network_intrusion",
            CaseType::RansomwareRecovery => "ransomware_recovery",
            CaseType::Litigation => "litigation",
            CaseType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "incident_response" => CaseType::IncidentResponse,
            "malware_analysis" => CaseType::MalwareAnalysis,
            "data_breach" => CaseType::DataBreach,
            "insider_threat" => CaseType::InsiderThreat,
            "network_intrusion" => CaseType::NetworkIntrusion,
            "ransomware_recovery" => CaseType::RansomwareRecovery,
            "litigation" => CaseType::Litigation,
            _ => CaseType::Other,
        }
    }
}

/// Case status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    InProgress,
    PendingReview,
    Closed,
    Archived,
}

impl CaseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaseStatus::Open => "open",
            CaseStatus::InProgress => "in_progress",
            CaseStatus::PendingReview => "pending_review",
            CaseStatus::Closed => "closed",
            CaseStatus::Archived => "archived",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "open" => CaseStatus::Open,
            "in_progress" => CaseStatus::InProgress,
            "pending_review" => CaseStatus::PendingReview,
            "closed" => CaseStatus::Closed,
            "archived" => CaseStatus::Archived,
            _ => CaseStatus::Open,
        }
    }
}

/// Forensic case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicCase {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub case_type: CaseType,
    pub status: CaseStatus,
    pub lead_analyst: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: String,
}

// =============================================================================
// Analysis Status
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Pending,
    Analyzing,
    Completed,
    Error,
}

impl AnalysisStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalysisStatus::Pending => "pending",
            AnalysisStatus::Analyzing => "analyzing",
            AnalysisStatus::Completed => "completed",
            AnalysisStatus::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pending" => AnalysisStatus::Pending,
            "analyzing" => AnalysisStatus::Analyzing,
            "completed" => AnalysisStatus::Completed,
            "error" => AnalysisStatus::Error,
            _ => AnalysisStatus::Pending,
        }
    }
}

// =============================================================================
// Severity Levels for Findings
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Critical => "critical",
            FindingSeverity::High => "high",
            FindingSeverity::Medium => "medium",
            FindingSeverity::Low => "low",
            FindingSeverity::Informational => "informational",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "critical" => FindingSeverity::Critical,
            "high" => FindingSeverity::High,
            "medium" => FindingSeverity::Medium,
            "low" => FindingSeverity::Low,
            "informational" => FindingSeverity::Informational,
            _ => FindingSeverity::Informational,
        }
    }
}

// =============================================================================
// Finding Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    MalwareDetected,
    SuspiciousProcess,
    PersistenceMechanism,
    DataExfiltration,
    LateralMovement,
    PrivilegeEscalation,
    CredentialAccess,
    Anomaly,
    IoC,
    TimelineEvent,
    Other,
}

impl FindingType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingType::MalwareDetected => "malware_detected",
            FindingType::SuspiciousProcess => "suspicious_process",
            FindingType::PersistenceMechanism => "persistence_mechanism",
            FindingType::DataExfiltration => "data_exfiltration",
            FindingType::LateralMovement => "lateral_movement",
            FindingType::PrivilegeEscalation => "privilege_escalation",
            FindingType::CredentialAccess => "credential_access",
            FindingType::Anomaly => "anomaly",
            FindingType::IoC => "ioc",
            FindingType::TimelineEvent => "timeline_event",
            FindingType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "malware_detected" => FindingType::MalwareDetected,
            "suspicious_process" => FindingType::SuspiciousProcess,
            "persistence_mechanism" => FindingType::PersistenceMechanism,
            "data_exfiltration" => FindingType::DataExfiltration,
            "lateral_movement" => FindingType::LateralMovement,
            "privilege_escalation" => FindingType::PrivilegeEscalation,
            "credential_access" => FindingType::CredentialAccess,
            "anomaly" => FindingType::Anomaly,
            "ioc" => FindingType::IoC,
            "timeline_event" => FindingType::TimelineEvent,
            _ => FindingType::Other,
        }
    }
}

/// Forensic finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFinding {
    pub id: String,
    pub case_id: String,
    pub finding_type: FindingType,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub evidence_refs: Vec<String>,
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// Timeline Event Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    FileCreated,
    FileModified,
    FileDeleted,
    FileAccessed,
    ProcessStarted,
    ProcessTerminated,
    NetworkConnection,
    RegistryModified,
    UserLogon,
    UserLogoff,
    ServiceInstalled,
    ServiceStarted,
    ServiceStopped,
    SoftwareInstalled,
    SoftwareUninstalled,
    SystemBoot,
    SystemShutdown,
    Other,
}

impl TimelineEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimelineEventType::FileCreated => "file_created",
            TimelineEventType::FileModified => "file_modified",
            TimelineEventType::FileDeleted => "file_deleted",
            TimelineEventType::FileAccessed => "file_accessed",
            TimelineEventType::ProcessStarted => "process_started",
            TimelineEventType::ProcessTerminated => "process_terminated",
            TimelineEventType::NetworkConnection => "network_connection",
            TimelineEventType::RegistryModified => "registry_modified",
            TimelineEventType::UserLogon => "user_logon",
            TimelineEventType::UserLogoff => "user_logoff",
            TimelineEventType::ServiceInstalled => "service_installed",
            TimelineEventType::ServiceStarted => "service_started",
            TimelineEventType::ServiceStopped => "service_stopped",
            TimelineEventType::SoftwareInstalled => "software_installed",
            TimelineEventType::SoftwareUninstalled => "software_uninstalled",
            TimelineEventType::SystemBoot => "system_boot",
            TimelineEventType::SystemShutdown => "system_shutdown",
            TimelineEventType::Other => "other",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "file_created" => TimelineEventType::FileCreated,
            "file_modified" => TimelineEventType::FileModified,
            "file_deleted" => TimelineEventType::FileDeleted,
            "file_accessed" => TimelineEventType::FileAccessed,
            "process_started" => TimelineEventType::ProcessStarted,
            "process_terminated" => TimelineEventType::ProcessTerminated,
            "network_connection" => TimelineEventType::NetworkConnection,
            "registry_modified" => TimelineEventType::RegistryModified,
            "user_logon" => TimelineEventType::UserLogon,
            "user_logoff" => TimelineEventType::UserLogoff,
            "service_installed" => TimelineEventType::ServiceInstalled,
            "service_started" => TimelineEventType::ServiceStarted,
            "service_stopped" => TimelineEventType::ServiceStopped,
            "software_installed" => TimelineEventType::SoftwareInstalled,
            "software_uninstalled" => TimelineEventType::SoftwareUninstalled,
            "system_boot" => TimelineEventType::SystemBoot,
            "system_shutdown" => TimelineEventType::SystemShutdown,
            _ => TimelineEventType::Other,
        }
    }
}

/// Timeline event entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub id: String,
    pub case_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: TimelineEventType,
    pub source: String,
    pub description: String,
    pub artifact_id: Option<String>,
}
