//! Core types for Incident Response module
//!
//! This module defines all data structures for incident response:
//! - Incident and its lifecycle states
//! - Timeline events and sources
//! - Evidence and chain of custody
//! - Response playbooks and actions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

// ============================================================================
// Incident Types
// ============================================================================

/// Incident severity levels (P1-P4)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IncidentSeverity {
    /// P1 - Critical: Business-critical systems affected, immediate response required
    P1,
    /// P2 - High: Significant impact, response within 4 hours
    P2,
    /// P3 - Medium: Moderate impact, response within 24 hours
    P3,
    /// P4 - Low: Minor impact, response within 72 hours
    P4,
}

impl std::fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentSeverity::P1 => write!(f, "P1"),
            IncidentSeverity::P2 => write!(f, "P2"),
            IncidentSeverity::P3 => write!(f, "P3"),
            IncidentSeverity::P4 => write!(f, "P4"),
        }
    }
}

impl std::str::FromStr for IncidentSeverity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "P1" | "CRITICAL" => Ok(IncidentSeverity::P1),
            "P2" | "HIGH" => Ok(IncidentSeverity::P2),
            "P3" | "MEDIUM" => Ok(IncidentSeverity::P3),
            "P4" | "LOW" => Ok(IncidentSeverity::P4),
            _ => Err(anyhow::anyhow!("Unknown severity: {}", s)),
        }
    }
}

impl Default for IncidentSeverity {
    fn default() -> Self {
        IncidentSeverity::P3
    }
}

/// Incident classification types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentClassification {
    /// Malware infection (ransomware, trojan, worm, etc.)
    Malware,
    /// Phishing attack
    Phishing,
    /// Data breach or data exfiltration
    DataBreach,
    /// Unauthorized access
    UnauthorizedAccess,
    /// Denial of service attack
    DenialOfService,
    /// Insider threat
    InsiderThreat,
    /// Web application attack
    WebAppAttack,
    /// Network intrusion
    NetworkIntrusion,
    /// Credential compromise
    CredentialCompromise,
    /// Social engineering
    SocialEngineering,
    /// Policy violation
    PolicyViolation,
    /// Suspicious activity (investigation needed)
    Suspicious,
    /// Other/uncategorized
    Other,
}

impl std::fmt::Display for IncidentClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentClassification::Malware => write!(f, "malware"),
            IncidentClassification::Phishing => write!(f, "phishing"),
            IncidentClassification::DataBreach => write!(f, "data_breach"),
            IncidentClassification::UnauthorizedAccess => write!(f, "unauthorized_access"),
            IncidentClassification::DenialOfService => write!(f, "denial_of_service"),
            IncidentClassification::InsiderThreat => write!(f, "insider_threat"),
            IncidentClassification::WebAppAttack => write!(f, "web_app_attack"),
            IncidentClassification::NetworkIntrusion => write!(f, "network_intrusion"),
            IncidentClassification::CredentialCompromise => write!(f, "credential_compromise"),
            IncidentClassification::SocialEngineering => write!(f, "social_engineering"),
            IncidentClassification::PolicyViolation => write!(f, "policy_violation"),
            IncidentClassification::Suspicious => write!(f, "suspicious"),
            IncidentClassification::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for IncidentClassification {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "malware" => Ok(IncidentClassification::Malware),
            "phishing" => Ok(IncidentClassification::Phishing),
            "data_breach" | "databreach" => Ok(IncidentClassification::DataBreach),
            "unauthorized_access" | "unauthorizedaccess" => Ok(IncidentClassification::UnauthorizedAccess),
            "denial_of_service" | "denialofservice" | "dos" | "ddos" => Ok(IncidentClassification::DenialOfService),
            "insider_threat" | "insiderthreat" => Ok(IncidentClassification::InsiderThreat),
            "web_app_attack" | "webappattack" => Ok(IncidentClassification::WebAppAttack),
            "network_intrusion" | "networkintrusion" => Ok(IncidentClassification::NetworkIntrusion),
            "credential_compromise" | "credentialcompromise" => Ok(IncidentClassification::CredentialCompromise),
            "social_engineering" | "socialengineering" => Ok(IncidentClassification::SocialEngineering),
            "policy_violation" | "policyviolation" => Ok(IncidentClassification::PolicyViolation),
            "suspicious" => Ok(IncidentClassification::Suspicious),
            "other" => Ok(IncidentClassification::Other),
            _ => Err(anyhow::anyhow!("Unknown classification: {}", s)),
        }
    }
}

impl Default for IncidentClassification {
    fn default() -> Self {
        IncidentClassification::Suspicious
    }
}

/// Incident lifecycle status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Incident has been detected but not yet acknowledged
    Detected,
    /// Incident is being triaged and analyzed
    Triaged,
    /// Containment measures are being applied
    Contained,
    /// Threat is being eradicated from the environment
    Eradicated,
    /// Systems are being recovered to normal operation
    Recovered,
    /// Incident is closed (resolved or false positive)
    Closed,
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncidentStatus::Detected => write!(f, "detected"),
            IncidentStatus::Triaged => write!(f, "triaged"),
            IncidentStatus::Contained => write!(f, "contained"),
            IncidentStatus::Eradicated => write!(f, "eradicated"),
            IncidentStatus::Recovered => write!(f, "recovered"),
            IncidentStatus::Closed => write!(f, "closed"),
        }
    }
}

impl std::str::FromStr for IncidentStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detected" => Ok(IncidentStatus::Detected),
            "triaged" => Ok(IncidentStatus::Triaged),
            "contained" => Ok(IncidentStatus::Contained),
            "eradicated" => Ok(IncidentStatus::Eradicated),
            "recovered" => Ok(IncidentStatus::Recovered),
            "closed" => Ok(IncidentStatus::Closed),
            _ => Err(anyhow::anyhow!("Unknown status: {}", s)),
        }
    }
}

impl Default for IncidentStatus {
    fn default() -> Self {
        IncidentStatus::Detected
    }
}

/// Main incident record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub classification: String,
    pub status: String,
    pub assignee_id: Option<String>,
    /// SLA breach deadline based on severity
    pub sla_breach_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    /// User who created this incident
    pub user_id: String,
    /// Optional organization for multi-tenant isolation
    pub organization_id: Option<String>,
}

/// Incident with related data for API responses
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IncidentWithDetails {
    #[serde(flatten)]
    pub incident: Incident,
    pub assignee_name: Option<String>,
    pub creator_name: Option<String>,
    pub alert_count: i32,
    pub ioc_count: i32,
    pub evidence_count: i32,
    pub timeline_event_count: i32,
}

// ============================================================================
// Timeline Types
// ============================================================================

/// Timeline event categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    /// Action taken by attacker
    AttackerAction,
    /// Action taken by defender
    DefenderAction,
    /// Automated system event
    SystemEvent,
    /// Alert triggered by monitoring
    Alert,
    /// Log entry from systems
    LogEntry,
    /// Manual observation or note
    Observation,
    /// Communication (email, chat, call)
    Communication,
    /// Evidence collected
    EvidenceCollected,
    /// Indicator of Compromise identified
    IocIdentified,
}

impl std::fmt::Display for TimelineEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimelineEventType::AttackerAction => write!(f, "attacker_action"),
            TimelineEventType::DefenderAction => write!(f, "defender_action"),
            TimelineEventType::SystemEvent => write!(f, "system_event"),
            TimelineEventType::Alert => write!(f, "alert"),
            TimelineEventType::LogEntry => write!(f, "log_entry"),
            TimelineEventType::Observation => write!(f, "observation"),
            TimelineEventType::Communication => write!(f, "communication"),
            TimelineEventType::EvidenceCollected => write!(f, "evidence_collected"),
            TimelineEventType::IocIdentified => write!(f, "ioc_identified"),
        }
    }
}

impl std::str::FromStr for TimelineEventType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "attacker_action" => Ok(TimelineEventType::AttackerAction),
            "defender_action" => Ok(TimelineEventType::DefenderAction),
            "system_event" => Ok(TimelineEventType::SystemEvent),
            "alert" => Ok(TimelineEventType::Alert),
            "log_entry" => Ok(TimelineEventType::LogEntry),
            "observation" => Ok(TimelineEventType::Observation),
            "communication" => Ok(TimelineEventType::Communication),
            "evidence_collected" => Ok(TimelineEventType::EvidenceCollected),
            "ioc_identified" => Ok(TimelineEventType::IocIdentified),
            _ => Err(anyhow::anyhow!("Unknown event type: {}", s)),
        }
    }
}

/// Timeline event record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct TimelineEvent {
    pub id: String,
    pub incident_id: String,
    pub event_type: String,
    /// When the event actually occurred
    pub timestamp: DateTime<Utc>,
    pub description: String,
    /// Source of the event (e.g., "SIEM", "EDR", "manual", "firewall")
    pub source: String,
    /// Actor involved (attacker IP, user, system, etc.)
    pub actor: Option<String>,
    /// User who created this entry
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// Timeline event with creator info for API responses
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TimelineEventWithCreator {
    #[serde(flatten)]
    pub event: TimelineEvent,
    pub creator_name: Option<String>,
}

// ============================================================================
// Evidence Types
// ============================================================================

/// Evidence type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// File (malware sample, document, etc.)
    File,
    /// Memory dump
    MemoryDump,
    /// Screenshot
    Screenshot,
    /// Log extract
    LogExtract,
    /// Network capture (PCAP)
    NetworkCapture,
    /// Disk image
    DiskImage,
    /// Registry export
    RegistryExport,
    /// Email (with headers)
    Email,
    /// Other evidence type
    Other,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::File => write!(f, "file"),
            EvidenceType::MemoryDump => write!(f, "memory_dump"),
            EvidenceType::Screenshot => write!(f, "screenshot"),
            EvidenceType::LogExtract => write!(f, "log_extract"),
            EvidenceType::NetworkCapture => write!(f, "network_capture"),
            EvidenceType::DiskImage => write!(f, "disk_image"),
            EvidenceType::RegistryExport => write!(f, "registry_export"),
            EvidenceType::Email => write!(f, "email"),
            EvidenceType::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for EvidenceType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "file" => Ok(EvidenceType::File),
            "memory_dump" | "memorydump" => Ok(EvidenceType::MemoryDump),
            "screenshot" => Ok(EvidenceType::Screenshot),
            "log_extract" | "logextract" | "log" => Ok(EvidenceType::LogExtract),
            "network_capture" | "networkcapture" | "pcap" => Ok(EvidenceType::NetworkCapture),
            "disk_image" | "diskimage" => Ok(EvidenceType::DiskImage),
            "registry_export" | "registryexport" | "registry" => Ok(EvidenceType::RegistryExport),
            "email" => Ok(EvidenceType::Email),
            "other" => Ok(EvidenceType::Other),
            _ => Err(anyhow::anyhow!("Unknown evidence type: {}", s)),
        }
    }
}

/// Evidence record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Evidence {
    pub id: String,
    pub incident_id: String,
    pub evidence_type: String,
    pub filename: String,
    /// SHA-256 hash for integrity verification
    pub file_hash: String,
    pub file_size: i64,
    /// Storage path (relative to evidence storage root)
    pub storage_path: String,
    pub collected_by: String,
    pub collected_at: DateTime<Utc>,
    pub notes: Option<String>,
    /// Comma-separated tags
    pub tags: Option<String>,
}

/// Evidence with collector info and custody count
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvidenceWithDetails {
    #[serde(flatten)]
    pub evidence: Evidence,
    pub collector_name: Option<String>,
    pub custody_entries: i32,
}

/// Chain of custody entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ChainOfCustody {
    pub id: String,
    pub evidence_id: String,
    /// Action taken (e.g., "collected", "transferred", "analyzed", "stored")
    pub action: String,
    pub actor_id: String,
    pub timestamp: DateTime<Utc>,
    pub notes: Option<String>,
}

/// Chain of custody with actor info
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChainOfCustodyWithActor {
    #[serde(flatten)]
    pub entry: ChainOfCustody,
    pub actor_name: Option<String>,
}

// ============================================================================
// Automation Types (SOAR-lite)
// ============================================================================

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    /// Block IP at firewall
    BlockIp,
    /// Disable user account
    DisableAccount,
    /// Isolate host from network
    IsolateHost,
    /// Quarantine file
    QuarantineFile,
    /// Reset user password
    ResetPassword,
    /// Revoke user sessions
    RevokeSessions,
    /// Kill process
    KillProcess,
    /// Collect forensic data
    CollectForensics,
    /// Send notification
    SendNotification,
    /// Create ticket in external system
    CreateTicket,
    /// Custom script execution
    CustomScript,
}

impl std::fmt::Display for ResponseActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseActionType::BlockIp => write!(f, "block_ip"),
            ResponseActionType::DisableAccount => write!(f, "disable_account"),
            ResponseActionType::IsolateHost => write!(f, "isolate_host"),
            ResponseActionType::QuarantineFile => write!(f, "quarantine_file"),
            ResponseActionType::ResetPassword => write!(f, "reset_password"),
            ResponseActionType::RevokeSessions => write!(f, "revoke_sessions"),
            ResponseActionType::KillProcess => write!(f, "kill_process"),
            ResponseActionType::CollectForensics => write!(f, "collect_forensics"),
            ResponseActionType::SendNotification => write!(f, "send_notification"),
            ResponseActionType::CreateTicket => write!(f, "create_ticket"),
            ResponseActionType::CustomScript => write!(f, "custom_script"),
        }
    }
}

impl std::str::FromStr for ResponseActionType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "block_ip" | "blockip" => Ok(ResponseActionType::BlockIp),
            "disable_account" | "disableaccount" => Ok(ResponseActionType::DisableAccount),
            "isolate_host" | "isolatehost" => Ok(ResponseActionType::IsolateHost),
            "quarantine_file" | "quarantinefile" => Ok(ResponseActionType::QuarantineFile),
            "reset_password" | "resetpassword" => Ok(ResponseActionType::ResetPassword),
            "revoke_sessions" | "revokesessions" => Ok(ResponseActionType::RevokeSessions),
            "kill_process" | "killprocess" => Ok(ResponseActionType::KillProcess),
            "collect_forensics" | "collectforensics" => Ok(ResponseActionType::CollectForensics),
            "send_notification" | "sendnotification" => Ok(ResponseActionType::SendNotification),
            "create_ticket" | "createticket" => Ok(ResponseActionType::CreateTicket),
            "custom_script" | "customscript" => Ok(ResponseActionType::CustomScript),
            _ => Err(anyhow::anyhow!("Unknown action type: {}", s)),
        }
    }
}

/// Response action status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// Action is pending approval
    Pending,
    /// Action has been approved
    Approved,
    /// Action has been executed
    Executed,
    /// Action failed during execution
    Failed,
    /// Action was rejected
    Rejected,
    /// Action was cancelled
    Cancelled,
}

impl std::fmt::Display for ActionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionStatus::Pending => write!(f, "pending"),
            ActionStatus::Approved => write!(f, "approved"),
            ActionStatus::Executed => write!(f, "executed"),
            ActionStatus::Failed => write!(f, "failed"),
            ActionStatus::Rejected => write!(f, "rejected"),
            ActionStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for ActionStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ActionStatus::Pending),
            "approved" => Ok(ActionStatus::Approved),
            "executed" => Ok(ActionStatus::Executed),
            "failed" => Ok(ActionStatus::Failed),
            "rejected" => Ok(ActionStatus::Rejected),
            "cancelled" => Ok(ActionStatus::Cancelled),
            _ => Err(anyhow::anyhow!("Unknown action status: {}", s)),
        }
    }
}

impl Default for ActionStatus {
    fn default() -> Self {
        ActionStatus::Pending
    }
}

/// Response playbook definition
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ResponsePlaybook {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// JSON object with trigger conditions (e.g., severity, classification)
    pub trigger_conditions: Option<String>,
    /// JSON array of playbook steps
    pub steps_json: String,
    /// Whether this is a built-in playbook
    pub is_builtin: bool,
    /// User who created this playbook (null for builtin)
    pub user_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Playbook step definition (stored as JSON in steps_json)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookStep {
    pub order: i32,
    pub name: String,
    pub description: Option<String>,
    pub action_type: String,
    /// JSON object with action-specific parameters
    pub parameters: Option<serde_json::Value>,
    /// Whether this step requires approval before execution
    pub requires_approval: bool,
    /// Timeout in seconds (null = no timeout)
    pub timeout_seconds: Option<i32>,
}

/// Response action record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ResponseAction {
    pub id: String,
    pub incident_id: String,
    pub playbook_id: Option<String>,
    pub action_type: String,
    /// Target of the action (IP, hostname, username, etc.)
    pub target: String,
    pub status: String,
    pub approved_by: Option<String>,
    pub executed_at: Option<DateTime<Utc>>,
    /// Result of the action (success message or error)
    pub result: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// Response action with approval info
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResponseActionWithDetails {
    #[serde(flatten)]
    pub action: ResponseAction,
    pub approver_name: Option<String>,
    pub creator_name: Option<String>,
    pub playbook_name: Option<String>,
}

/// Action audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct ActionAuditLog {
    pub id: String,
    pub action_id: String,
    /// Event type (e.g., "created", "approved", "executed", "failed")
    pub event: String,
    /// Additional details as JSON
    pub details: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request to create a new incident
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateIncidentRequest {
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub classification: String,
    pub assignee_id: Option<String>,
}

/// Request to update an incident
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateIncidentRequest {
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub classification: Option<String>,
}

/// Request to update incident status
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateIncidentStatusRequest {
    pub status: String,
    pub notes: Option<String>,
}

/// Request to assign an incident
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AssignIncidentRequest {
    pub assignee_id: Option<String>,
}

/// Request to create a timeline event
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateTimelineEventRequest {
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub source: String,
    pub actor: Option<String>,
}

/// Request to create evidence
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateEvidenceRequest {
    pub evidence_type: String,
    pub filename: String,
    pub file_hash: String,
    pub file_size: i64,
    pub storage_path: String,
    pub notes: Option<String>,
    pub tags: Option<String>,
}

/// Request to add chain of custody entry
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AddCustodyEntryRequest {
    pub action: String,
    pub notes: Option<String>,
}

/// Request to create a response playbook
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreatePlaybookRequest {
    pub name: String,
    pub description: Option<String>,
    pub trigger_conditions: Option<serde_json::Value>,
    pub steps: Vec<PlaybookStep>,
}

/// Request to update a playbook
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdatePlaybookRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub trigger_conditions: Option<serde_json::Value>,
    pub steps: Option<Vec<PlaybookStep>>,
}

/// Request to execute a response action
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ExecuteActionRequest {
    pub action_type: String,
    pub target: String,
    pub playbook_id: Option<String>,
}

/// Request to approve/reject an action
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ApproveActionRequest {
    pub approved: bool,
    pub notes: Option<String>,
}

/// Timeline export format
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TimelineExportFormat {
    Json,
    Csv,
    Pdf,
}

impl Default for TimelineExportFormat {
    fn default() -> Self {
        TimelineExportFormat::Json
    }
}

/// IR Dashboard statistics
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IncidentDashboardStats {
    pub total_incidents: i64,
    pub open_incidents: i64,
    pub incidents_by_severity: Vec<SeverityCount>,
    pub incidents_by_status: Vec<StatusCount>,
    pub incidents_by_classification: Vec<ClassificationCount>,
    pub sla_breaches: i64,
    pub mean_time_to_contain_hours: Option<f64>,
    pub mean_time_to_close_hours: Option<f64>,
    pub recent_incidents: Vec<Incident>,
    pub pending_actions: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SeverityCount {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatusCount {
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClassificationCount {
    pub classification: String,
    pub count: i64,
}

/// Incident-Alert linking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IncidentAlert {
    pub incident_id: String,
    pub alert_id: String,
}

/// Incident-IOC linking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IncidentIoc {
    pub incident_id: String,
    pub ioc_id: String,
}
