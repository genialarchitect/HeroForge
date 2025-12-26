//! Core SOAR types for the Green Team module

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// Playbook Types
// ============================================================================

/// A SOAR playbook that can be executed manually or automatically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub category: PlaybookCategory,
    pub trigger: PlaybookTrigger,
    pub steps: Vec<PlaybookStep>,
    pub is_active: bool,
    pub is_template: bool,
    pub marketplace_id: Option<String>,
    pub version: String,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Categories of playbooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookCategory {
    IncidentResponse,
    ThreatHunting,
    Compliance,
    Enrichment,
    Remediation,
    Notification,
    Custom,
}

impl std::fmt::Display for PlaybookCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncidentResponse => write!(f, "incident_response"),
            Self::ThreatHunting => write!(f, "threat_hunting"),
            Self::Compliance => write!(f, "compliance"),
            Self::Enrichment => write!(f, "enrichment"),
            Self::Remediation => write!(f, "remediation"),
            Self::Notification => write!(f, "notification"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// What triggers a playbook to run
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaybookTrigger {
    Manual,
    Alert {
        alert_types: Vec<String>,
        severity_min: Option<Severity>,
    },
    Schedule {
        cron: String,
    },
    Webhook {
        secret: String,
    },
    Ioc {
        ioc_types: Vec<String>,
    },
    Event {
        event_types: Vec<String>,
    },
}

/// A step within a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub action: PlaybookAction,
    pub condition: Option<StepCondition>,
    pub on_success: Option<String>,
    pub on_failure: Option<String>,
    pub timeout_seconds: u32,
    pub retry_count: Option<u32>,
}

/// Actions that can be performed in a playbook step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlaybookAction {
    HttpRequest {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    SendNotification {
        channel: NotificationChannel,
        template: String,
        recipients: Vec<String>,
    },
    CreateCase {
        title: String,
        severity: Severity,
        case_type: CaseType,
        assign_to: Option<String>,
    },
    EnrichIoc {
        ioc_type: String,
        value_template: String,
        sources: Vec<String>,
    },
    RunScript {
        script: String,
        interpreter: String,
        args: Vec<String>,
    },
    BlockIp {
        ip_template: String,
        firewall: String,
        duration_hours: Option<u32>,
    },
    IsolateHost {
        hostname_template: String,
        agent_type: String,
    },
    CreateTicket {
        system: TicketSystem,
        title: String,
        description: String,
        priority: String,
    },
    WaitForApproval {
        approvers: Vec<String>,
        timeout_hours: u32,
        message: String,
    },
    Parallel {
        steps: Vec<PlaybookStep>,
    },
    Conditional {
        condition: StepCondition,
        then_steps: Vec<PlaybookStep>,
        else_steps: Vec<PlaybookStep>,
    },
    SetVariable {
        name: String,
        value: String,
    },
    Wait {
        seconds: u32,
    },
    AddEvidence {
        case_id_template: String,
        evidence_type: EvidenceType,
        data_template: String,
    },
}

/// Notification channel types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Slack,
    Teams,
    Webhook,
    Sms,
    PagerDuty,
}

/// Ticketing systems
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketSystem {
    Jira,
    ServiceNow,
    Zendesk,
    GitHub,
    Custom,
}

/// Condition for step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

/// Condition operators
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Matches,
    IsNull,
    IsNotNull,
    In,
    NotIn,
}

/// Status of a playbook run
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookRunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    WaitingApproval,
}

impl std::fmt::Display for PlaybookRunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::WaitingApproval => write!(f, "waiting_approval"),
        }
    }
}

/// A single execution of a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRun {
    pub id: Uuid,
    pub playbook_id: Uuid,
    pub trigger_type: String,
    pub trigger_source: Option<String>,
    pub status: PlaybookRunStatus,
    pub current_step: u32,
    pub total_steps: u32,
    pub input_data: Option<serde_json::Value>,
    pub output_data: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_seconds: Option<u32>,
}

// ============================================================================
// Case Management Types
// ============================================================================

/// Severity levels
#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Medium,
    High,
    Urgent,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Urgent => write!(f, "urgent"),
        }
    }
}

/// Types of cases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseType {
    Incident,
    Investigation,
    ThreatHunt,
    Vulnerability,
    Compliance,
    Other,
}

impl std::fmt::Display for CaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incident => write!(f, "incident"),
            Self::Investigation => write!(f, "investigation"),
            Self::ThreatHunt => write!(f, "threat_hunt"),
            Self::Vulnerability => write!(f, "vulnerability"),
            Self::Compliance => write!(f, "compliance"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Status of a case
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    InProgress,
    Pending,
    Resolved,
    Closed,
}

impl std::fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Pending => write!(f, "pending"),
            Self::Resolved => write!(f, "resolved"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Traffic Light Protocol for sharing
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
    White,
    Green,
    Amber,
    Red,
}

impl std::fmt::Display for Tlp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::White => write!(f, "white"),
            Self::Green => write!(f, "green"),
            Self::Amber => write!(f, "amber"),
            Self::Red => write!(f, "red"),
        }
    }
}

/// A security case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarCase {
    pub id: Uuid,
    pub case_number: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub status: CaseStatus,
    pub priority: Priority,
    pub case_type: CaseType,
    pub assignee_id: Option<Uuid>,
    pub source: Option<String>,
    pub source_ref: Option<String>,
    pub tlp: Tlp,
    pub tags: Vec<String>,
    pub resolution: Option<String>,
    pub resolution_time_hours: Option<f64>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
}

/// A task within a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseTask {
    pub id: Uuid,
    pub case_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub status: TaskStatus,
    pub priority: Priority,
    pub assignee_id: Option<Uuid>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Status of a task
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Blocked,
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Completed => write!(f, "completed"),
            Self::Blocked => write!(f, "blocked"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Evidence attached to a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvidence {
    pub id: Uuid,
    pub case_id: Uuid,
    pub evidence_type: EvidenceType,
    pub name: String,
    pub description: Option<String>,
    pub file_path: Option<String>,
    pub hash_sha256: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub collected_by: Uuid,
    pub collected_at: DateTime<Utc>,
}

/// Types of evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    File,
    Log,
    Screenshot,
    Ioc,
    Artifact,
    NetworkCapture,
    MemoryDump,
    Other,
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Log => write!(f, "log"),
            Self::Screenshot => write!(f, "screenshot"),
            Self::Ioc => write!(f, "ioc"),
            Self::Artifact => write!(f, "artifact"),
            Self::NetworkCapture => write!(f, "network_capture"),
            Self::MemoryDump => write!(f, "memory_dump"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Case comment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseComment {
    pub id: Uuid,
    pub case_id: Uuid,
    pub user_id: Uuid,
    pub content: String,
    pub is_internal: bool,
    pub created_at: DateTime<Utc>,
}

/// Case timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseTimelineEvent {
    pub id: Uuid,
    pub case_id: Uuid,
    pub event_type: TimelineEventType,
    pub event_data: serde_json::Value,
    pub user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Types of timeline events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventType {
    Created,
    StatusChange,
    Assignment,
    Comment,
    Evidence,
    Task,
    Playbook,
    Resolution,
    Reopened,
}

// ============================================================================
// Threat Intel Automation Types
// ============================================================================

/// An IOC feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeed {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub feed_type: IocFeedType,
    pub url: String,
    pub api_key: Option<String>,
    pub poll_interval_minutes: u32,
    pub is_active: bool,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub last_poll_status: Option<String>,
    pub ioc_count: u32,
    pub created_at: DateTime<Utc>,
}

/// Types of IOC feeds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IocFeedType {
    Stix,
    Csv,
    Json,
    Taxii,
    Misp,
    OpenIoc,
    Custom,
}

impl std::fmt::Display for IocFeedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stix => write!(f, "stix"),
            Self::Csv => write!(f, "csv"),
            Self::Json => write!(f, "json"),
            Self::Taxii => write!(f, "taxii"),
            Self::Misp => write!(f, "misp"),
            Self::OpenIoc => write!(f, "openioc"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// An IOC from an automated feed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedIoc {
    pub id: Uuid,
    pub feed_id: Uuid,
    pub ioc_type: IocType,
    pub value: String,
    pub confidence: Option<f64>,
    pub severity: Option<Severity>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub enrichment_data: Option<serde_json::Value>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Types of IOCs
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    FileHash,
    FileName,
    Registry,
    Mutex,
    UserAgent,
    Cidr,
    Asn,
    Bitcoin,
    Cve,
    Other,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4 => write!(f, "ipv4"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Domain => write!(f, "domain"),
            Self::Url => write!(f, "url"),
            Self::Email => write!(f, "email"),
            Self::FileHash => write!(f, "file_hash"),
            Self::FileName => write!(f, "file_name"),
            Self::Registry => write!(f, "registry"),
            Self::Mutex => write!(f, "mutex"),
            Self::UserAgent => write!(f, "user_agent"),
            Self::Cidr => write!(f, "cidr"),
            Self::Asn => write!(f, "asn"),
            Self::Bitcoin => write!(f, "bitcoin"),
            Self::Cve => write!(f, "cve"),
            Self::Other => write!(f, "other"),
        }
    }
}

// ============================================================================
// Response Metrics Types
// ============================================================================

/// Response metrics for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetrics {
    pub metric_date: chrono::NaiveDate,
    pub total_cases: u32,
    pub cases_opened: u32,
    pub cases_closed: u32,
    pub avg_mttd_minutes: Option<f64>,
    pub avg_mttr_minutes: Option<f64>,
    pub avg_mttc_minutes: Option<f64>,
    pub avg_resolution_hours: Option<f64>,
    pub sla_met_count: u32,
    pub sla_breached_count: u32,
    pub playbooks_executed: u32,
}

/// SLA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    pub id: Uuid,
    pub name: String,
    pub severity: Severity,
    pub response_time_minutes: u32,
    pub resolution_time_hours: u32,
    pub escalation_time_minutes: Option<u32>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Metrics overview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsOverview {
    pub total_cases: u32,
    pub open_cases: u32,
    pub resolved_today: u32,
    pub avg_mttd_minutes: f64,
    pub avg_mttr_minutes: f64,
    pub sla_compliance_rate: f64,
    pub playbooks_executed: u32,
    pub automation_rate: f64,
}

// ============================================================================
// Marketplace Types
// ============================================================================

/// A playbook in the marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlaybook {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub author: String,
    pub category: PlaybookCategory,
    pub tags: Vec<String>,
    pub version: String,
    pub downloads: u32,
    pub rating: f64,
    pub ratings_count: u32,
    pub playbook_json: serde_json::Value,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Rating for a marketplace playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRating {
    pub id: Uuid,
    pub playbook_id: Uuid,
    pub user_id: Uuid,
    pub rating: u8,
    pub review: Option<String>,
    pub helpful_votes: u32,
    pub created_at: DateTime<Utc>,
}
