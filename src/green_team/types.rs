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

    // ========== Enrichment Actions (10) ==========
    LookupIpReputation {
        ip_template: String,
        sources: Vec<String>,
    },
    LookupDomainReputation {
        domain_template: String,
        sources: Vec<String>,
    },
    LookupFileHash {
        hash_template: String,
        hash_type: String, // md5, sha1, sha256
        sources: Vec<String>,
    },
    LookupUrlReputation {
        url_template: String,
        sources: Vec<String>,
    },
    GeolocateIp {
        ip_template: String,
    },
    WhoisLookup {
        domain_template: String,
    },
    DnsLookup {
        hostname_template: String,
        record_type: String, // A, AAAA, MX, TXT, etc.
    },
    ReverseDnsLookup {
        ip_template: String,
    },
    GetCertificateInfo {
        domain_template: String,
    },
    EnrichUser {
        username_template: String,
        sources: Vec<String>, // AD, LDAP, HR system
    },

    // ========== Containment Actions (10) ==========
    BlockDomain {
        domain_template: String,
        dns_firewall: String,
        duration_hours: Option<u32>,
    },
    BlockUrl {
        url_template: String,
        proxy_system: String,
        duration_hours: Option<u32>,
    },
    QuarantineFile {
        file_path_template: String,
        host_template: String,
        agent_type: String,
    },
    DisableUser {
        username_template: String,
        directory: String, // AD, LDAP, local
    },
    RevokeAccessToken {
        token_id_template: String,
        system: String,
    },
    DisableServiceAccount {
        account_template: String,
        system: String,
    },
    BlockEmailSender {
        sender_template: String,
        email_gateway: String,
    },
    IsolateNetwork {
        vlan_template: String,
        switch: String,
    },
    ShutdownHost {
        hostname_template: String,
        agent_type: String,
    },
    BlockProcess {
        process_name_template: String,
        host_template: String,
        agent_type: String,
    },

    // ========== Investigation Actions (8) ==========
    QuerySiem {
        query: String,
        time_range: String,
        siem_type: String, // splunk, elastic, qradar
    },
    SearchLogs {
        query: String,
        log_source: String,
        time_range: String,
    },
    GetProcessList {
        host_template: String,
        agent_type: String,
    },
    GetNetworkConnections {
        host_template: String,
        agent_type: String,
    },
    GetFileInfo {
        file_path_template: String,
        host_template: String,
    },
    CaptureMemoryDump {
        host_template: String,
        process_template: Option<String>,
    },
    CollectArtifacts {
        host_template: String,
        artifact_types: Vec<String>, // registry, logs, files
    },
    AnalyzePacketCapture {
        pcap_path_template: String,
        filters: Option<String>,
    },

    // ========== Remediation Actions (7) ==========
    KillProcess {
        process_identifier: String, // PID or name
        host_template: String,
        agent_type: String,
    },
    DeleteFile {
        file_path_template: String,
        host_template: String,
    },
    RestoreFromBackup {
        file_path_template: String,
        backup_timestamp: String,
        host_template: String,
    },
    PatchSystem {
        host_template: String,
        patches: Vec<String>, // KB numbers or package names
    },
    ResetPassword {
        username_template: String,
        directory: String,
    },
    RevokeCredentials {
        username_template: String,
        system: String,
    },
    UpdateFirewallRule {
        rule_name: String,
        firewall: String,
        action: String, // add, remove, modify
        config: HashMap<String, String>,
    },

    // ========== Integration Actions (8) ==========
    SplunkQuery {
        query: String,
        earliest: String,
        latest: String,
    },
    ElasticQuery {
        index: String,
        query: String,
        time_range: String,
    },
    CarbonBlackAction {
        action: String, // isolate, remediate, ban_hash
        target: String,
    },
    CrowdStrikeAction {
        action: String,
        host_id_template: String,
    },
    SentinelOneAction {
        action: String,
        agent_id_template: String,
    },
    PaloAltoAction {
        action: String, // block_ip, create_rule
        config: HashMap<String, String>,
    },
    ActiveDirectoryQuery {
        ldap_query: String,
        attributes: Vec<String>,
    },
    ServiceNowUpdate {
        ticket_number: String,
        fields: HashMap<String, String>,
    },

    // ========== Data/Utility Actions (10) ==========
    ForEach {
        items: String, // variable name or expression
        loop_variable: String,
        steps: Vec<PlaybookStep>,
    },
    ParseJson {
        json_template: String,
        output_variable: String,
    },
    ParseXml {
        xml_template: String,
        output_variable: String,
    },
    ExtractRegex {
        input_template: String,
        pattern: String,
        output_variable: String,
    },
    TransformData {
        input_template: String,
        transformation: String, // jq, jsonpath
        output_variable: String,
    },
    FormatString {
        template: String,
        output_variable: String,
    },
    MathOperation {
        operation: String, // add, subtract, multiply, divide
        operands: Vec<String>,
        output_variable: String,
    },
    JoinStrings {
        strings: Vec<String>,
        separator: String,
        output_variable: String,
    },
    SplitString {
        input_template: String,
        delimiter: String,
        output_variable: String,
    },
    Base64Encode {
        input_template: String,
        output_variable: String,
    },
    Base64Decode {
        input_template: String,
        output_variable: String,
    },

    // ========== Response Actions (5) ==========
    SendAlert {
        severity: Severity,
        title: String,
        description: String,
        recipients: Vec<String>,
    },
    UpdateCaseStatus {
        case_id_template: String,
        status: String,
        notes: Option<String>,
    },
    AssignCase {
        case_id_template: String,
        assignee: String,
    },
    AddCaseComment {
        case_id_template: String,
        comment: String,
    },
    CloseCase {
        case_id_template: String,
        resolution: String,
        notes: String,
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
    Text,
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
            Self::Text => write!(f, "text"),
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

// ============================================================================
// SOAR Foundation Enhancement Types (Sprint 11-12)
// ============================================================================

/// Risk level for actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Action category for the action library
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionCategory {
    Enrichment,
    Notification,
    Containment,
    Remediation,
    Utility,
    Siem,
    Edr,
    Custom,
}

impl std::fmt::Display for ActionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enrichment => write!(f, "enrichment"),
            Self::Notification => write!(f, "notification"),
            Self::Containment => write!(f, "containment"),
            Self::Remediation => write!(f, "remediation"),
            Self::Utility => write!(f, "utility"),
            Self::Siem => write!(f, "siem"),
            Self::Edr => write!(f, "edr"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Action type for the action library
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Api,
    Script,
    Builtin,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api => write!(f, "api"),
            Self::Script => write!(f, "script"),
            Self::Builtin => write!(f, "builtin"),
        }
    }
}

/// A library action definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarActionDefinition {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub category: ActionCategory,
    pub integration: Option<String>,
    pub action_type: ActionType,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub timeout_seconds: i32,
    pub requires_approval: bool,
    pub risk_level: RiskLevel,
    pub enabled: bool,
    pub custom: bool,
    pub icon: Option<String>,
    pub documentation_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Step execution record - detailed tracking of each step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExecution {
    pub id: Uuid,
    pub run_id: Uuid,
    pub step_id: String,
    pub step_index: i32,
    pub action_id: Option<String>,
    pub action_name: String,
    pub status: StepExecutionStatus,
    pub input_data: Option<serde_json::Value>,
    pub output_data: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub retries: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub created_at: DateTime<Utc>,
}

/// Status of a step execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    WaitingApproval,
    Cancelled,
}

impl std::fmt::Display for StepExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
            Self::WaitingApproval => write!(f, "waiting_approval"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Approval request for high-risk actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarApproval {
    pub id: Uuid,
    pub run_id: Uuid,
    pub step_id: String,
    pub step_name: String,
    pub action_description: Option<String>,
    pub approvers: Vec<String>,
    pub required_approvals: i32,
    pub current_approvals: i32,
    pub status: ApprovalStatus,
    pub timeout_at: Option<DateTime<Utc>>,
    pub decisions: Vec<ApprovalDecision>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Status of an approval request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Timeout,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

/// Individual approval decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub id: Uuid,
    pub approval_id: Uuid,
    pub user_id: String,
    pub username: Option<String>,
    pub decision: String,
    pub comments: Option<String>,
    pub decided_at: DateTime<Utc>,
}

/// SOAR integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarIntegration {
    pub id: Uuid,
    pub user_id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub vendor: Option<String>,
    pub config: serde_json::Value,
    pub status: IntegrationStatus,
    pub last_test_at: Option<DateTime<Utc>>,
    pub last_test_status: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Types of integrations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationType {
    Siem,
    Edr,
    Firewall,
    Ticketing,
    Email,
    Slack,
    Teams,
    Webhook,
    ThreatIntel,
    Directory,
    CloudProvider,
    Custom,
}

impl std::fmt::Display for IntegrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Siem => write!(f, "siem"),
            Self::Edr => write!(f, "edr"),
            Self::Firewall => write!(f, "firewall"),
            Self::Ticketing => write!(f, "ticketing"),
            Self::Email => write!(f, "email"),
            Self::Slack => write!(f, "slack"),
            Self::Teams => write!(f, "teams"),
            Self::Webhook => write!(f, "webhook"),
            Self::ThreatIntel => write!(f, "threat_intel"),
            Self::Directory => write!(f, "directory"),
            Self::CloudProvider => write!(f, "cloud_provider"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// Integration connection status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    Connected,
    Disconnected,
    Error,
    Testing,
}

impl std::fmt::Display for IntegrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Error => write!(f, "error"),
            Self::Testing => write!(f, "testing"),
        }
    }
}

/// Playbook variable definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookVariable {
    pub id: Uuid,
    pub playbook_id: Uuid,
    pub name: String,
    pub variable_type: VariableType,
    pub default_value: Option<String>,
    pub description: Option<String>,
    pub is_required: bool,
    pub is_secret: bool,
    pub created_at: DateTime<Utc>,
}

/// Variable types for playbook variables
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VariableType {
    String,
    Number,
    Boolean,
    Array,
    Object,
    Secret,
}

impl std::fmt::Display for VariableType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Number => write!(f, "number"),
            Self::Boolean => write!(f, "boolean"),
            Self::Array => write!(f, "array"),
            Self::Object => write!(f, "object"),
            Self::Secret => write!(f, "secret"),
        }
    }
}

/// Playbook trigger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarTrigger {
    pub id: Uuid,
    pub playbook_id: Uuid,
    pub name: String,
    pub trigger_type: TriggerType,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub trigger_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Trigger types for playbooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    Manual,
    Schedule,
    Webhook,
    Alert,
    Event,
    Api,
}

impl std::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manual => write!(f, "manual"),
            Self::Schedule => write!(f, "schedule"),
            Self::Webhook => write!(f, "webhook"),
            Self::Alert => write!(f, "alert"),
            Self::Event => write!(f, "event"),
            Self::Api => write!(f, "api"),
        }
    }
}

/// Webhook endpoint for external triggering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub playbook_id: Uuid,
    pub name: String,
    pub url_token: String,
    pub secret: Option<String>,
    pub enabled: bool,
    pub request_count: i32,
    pub last_request_at: Option<DateTime<Utc>>,
    pub allowed_ips: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
}

/// SOAR audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarAuditEntry {
    pub id: Uuid,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// SOAR dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarStats {
    pub total_playbooks: i32,
    pub active_playbooks: i32,
    pub total_runs_today: i32,
    pub successful_runs_today: i32,
    pub failed_runs_today: i32,
    pub pending_approvals: i32,
    pub total_actions: i32,
    pub total_integrations: i32,
    pub connected_integrations: i32,
    pub avg_run_duration_ms: Option<i64>,
    pub automation_rate: f64,
}

/// Daily metrics aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarMetricsDaily {
    pub id: Uuid,
    pub metric_date: chrono::NaiveDate,
    pub playbook_id: Option<Uuid>,
    pub total_runs: i32,
    pub successful_runs: i32,
    pub failed_runs: i32,
    pub avg_duration_ms: Option<i64>,
    pub min_duration_ms: Option<i64>,
    pub max_duration_ms: Option<i64>,
    pub total_steps_executed: i32,
    pub approvals_requested: i32,
    pub approvals_approved: i32,
    pub approvals_rejected: i32,
    pub created_at: DateTime<Utc>,
}

/// Execution context passed through playbook steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub run_id: Uuid,
    pub playbook_id: Uuid,
    pub playbook_name: String,
    pub trigger_type: String,
    pub trigger_source: Option<String>,
    pub input_data: serde_json::Value,
    pub variables: HashMap<String, serde_json::Value>,
    pub step_outputs: HashMap<String, serde_json::Value>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub initiated_by: Option<String>,
    pub started_at: DateTime<Utc>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(
        run_id: Uuid,
        playbook_id: Uuid,
        playbook_name: String,
        trigger_type: String,
        input_data: serde_json::Value,
    ) -> Self {
        Self {
            run_id,
            playbook_id,
            playbook_name,
            trigger_type,
            trigger_source: None,
            input_data,
            variables: HashMap::new(),
            step_outputs: HashMap::new(),
            customer_id: None,
            engagement_id: None,
            initiated_by: None,
            started_at: Utc::now(),
        }
    }

    /// Set a variable
    pub fn set_variable(&mut self, name: &str, value: serde_json::Value) {
        self.variables.insert(name.to_string(), value);
    }

    /// Get a variable
    pub fn get_variable(&self, name: &str) -> Option<&serde_json::Value> {
        self.variables.get(name)
    }

    /// Store step output
    pub fn store_step_output(&mut self, step_id: &str, output: serde_json::Value) {
        self.step_outputs.insert(step_id.to_string(), output);
    }

    /// Get step output
    pub fn get_step_output(&self, step_id: &str) -> Option<&serde_json::Value> {
        self.step_outputs.get(step_id)
    }
}

/// Result of a step execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub success: bool,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: i64,
    pub requires_approval: bool,
}

impl StepResult {
    /// Create a successful step result
    pub fn success(step_id: String, output: serde_json::Value, duration_ms: i64) -> Self {
        Self {
            step_id,
            success: true,
            output: Some(output),
            error: None,
            duration_ms,
            requires_approval: false,
        }
    }

    /// Create a failed step result
    pub fn failure(step_id: String, error: String, duration_ms: i64) -> Self {
        Self {
            step_id,
            success: false,
            output: None,
            error: Some(error),
            duration_ms,
            requires_approval: false,
        }
    }

    /// Create a result requiring approval
    pub fn requires_approval(step_id: String, duration_ms: i64) -> Self {
        Self {
            step_id,
            success: false,
            output: None,
            error: None,
            duration_ms,
            requires_approval: true,
        }
    }
}
