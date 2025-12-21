#![allow(dead_code)]
//! Workflow types and definitions for remediation workflows
//!
//! This module defines the core types for configurable approval chains:
//! - WorkflowTemplate: Reusable workflow definitions
//! - WorkflowStage: Individual stages within a template
//! - WorkflowInstance: Active workflow executions
//! - WorkflowApproval: Approval records

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

// ============================================================================
// Workflow Template Types
// ============================================================================

/// A reusable workflow template definition
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowTemplate {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Whether this is a system-defined template
    pub is_system: bool,
    /// User who created this template (null for system templates)
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Whether this template is active and can be used
    pub is_active: bool,
}

/// A stage within a workflow template
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowStage {
    pub id: String,
    pub template_id: String,
    /// Display name for this stage
    pub name: String,
    pub description: Option<String>,
    /// Order of this stage in the workflow (0-indexed)
    pub stage_order: i32,
    /// Stage type determines behavior
    pub stage_type: String,
    /// Number of approvals required to advance (0 = auto-advance)
    pub required_approvals: i32,
    /// Role required to approve (null = any authenticated user)
    pub approver_role: Option<String>,
    /// Specific user IDs who can approve (JSON array, null = role-based)
    pub approver_user_ids: Option<String>,
    /// SLA in hours for this stage (null = no SLA)
    pub sla_hours: Option<i32>,
    /// Whether to send notifications when entering this stage
    pub notify_on_enter: bool,
    /// Whether to send notifications on SLA breach
    pub notify_on_sla_breach: bool,
    /// Auto-advance conditions (JSON object, null = manual advancement)
    pub auto_advance_conditions: Option<String>,
}

/// Stage types that define behavior
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageType {
    /// Assignment stage - vulnerability gets assigned
    Assignment,
    /// Work stage - actual remediation work
    Work,
    /// Review stage - requires approval
    Review,
    /// Verification stage - security team verifies fix
    Verification,
    /// CAB (Change Advisory Board) approval
    CabApproval,
    /// Deployment stage
    Deployment,
    /// Final closure stage
    Closure,
}

impl std::fmt::Display for StageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageType::Assignment => write!(f, "assignment"),
            StageType::Work => write!(f, "work"),
            StageType::Review => write!(f, "review"),
            StageType::Verification => write!(f, "verification"),
            StageType::CabApproval => write!(f, "cab_approval"),
            StageType::Deployment => write!(f, "deployment"),
            StageType::Closure => write!(f, "closure"),
        }
    }
}

impl std::str::FromStr for StageType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "assignment" => Ok(StageType::Assignment),
            "work" => Ok(StageType::Work),
            "review" => Ok(StageType::Review),
            "verification" => Ok(StageType::Verification),
            "cab_approval" => Ok(StageType::CabApproval),
            "deployment" => Ok(StageType::Deployment),
            "closure" => Ok(StageType::Closure),
            _ => Err(anyhow::anyhow!("Unknown stage type: {}", s)),
        }
    }
}

// ============================================================================
// Workflow Instance Types
// ============================================================================

/// An active workflow execution for a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowInstance {
    pub id: String,
    pub template_id: String,
    /// The vulnerability this workflow is for
    pub vulnerability_id: String,
    /// Current stage ID
    pub current_stage_id: String,
    /// Overall workflow status
    pub status: String,
    /// User who started this workflow
    pub started_by: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Optional notes about workflow
    pub notes: Option<String>,
}

/// Status of a workflow instance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    /// Workflow is active and in progress
    Active,
    /// Workflow completed successfully
    Completed,
    /// Workflow was cancelled
    Cancelled,
    /// Workflow is on hold
    OnHold,
    /// Workflow was rejected at some stage
    Rejected,
}

impl std::fmt::Display for WorkflowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowStatus::Active => write!(f, "active"),
            WorkflowStatus::Completed => write!(f, "completed"),
            WorkflowStatus::Cancelled => write!(f, "cancelled"),
            WorkflowStatus::OnHold => write!(f, "on_hold"),
            WorkflowStatus::Rejected => write!(f, "rejected"),
        }
    }
}

impl std::str::FromStr for WorkflowStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(WorkflowStatus::Active),
            "completed" => Ok(WorkflowStatus::Completed),
            "cancelled" => Ok(WorkflowStatus::Cancelled),
            "on_hold" => Ok(WorkflowStatus::OnHold),
            "rejected" => Ok(WorkflowStatus::Rejected),
            _ => Err(anyhow::anyhow!("Unknown workflow status: {}", s)),
        }
    }
}

/// Status of an individual stage instance
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowStageInstance {
    pub id: String,
    pub instance_id: String,
    pub stage_id: String,
    /// Stage status
    pub status: String,
    pub entered_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// SLA deadline calculated from entered_at + stage.sla_hours
    pub sla_deadline: Option<DateTime<Utc>>,
    /// Whether SLA has been breached
    pub sla_breached: bool,
    /// Number of approvals received
    pub approvals_received: i32,
    /// Notes specific to this stage
    pub notes: Option<String>,
}

/// Status of a stage instance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    /// Stage is pending, not yet entered
    Pending,
    /// Stage is currently active
    Active,
    /// Stage completed successfully
    Completed,
    /// Stage was skipped
    Skipped,
    /// Stage was rejected (workflow may restart or fail)
    Rejected,
}

impl std::fmt::Display for StageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageStatus::Pending => write!(f, "pending"),
            StageStatus::Active => write!(f, "active"),
            StageStatus::Completed => write!(f, "completed"),
            StageStatus::Skipped => write!(f, "skipped"),
            StageStatus::Rejected => write!(f, "rejected"),
        }
    }
}

impl std::str::FromStr for StageStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(StageStatus::Pending),
            "active" => Ok(StageStatus::Active),
            "completed" => Ok(StageStatus::Completed),
            "skipped" => Ok(StageStatus::Skipped),
            "rejected" => Ok(StageStatus::Rejected),
            _ => Err(anyhow::anyhow!("Unknown stage status: {}", s)),
        }
    }
}

// ============================================================================
// Approval Types
// ============================================================================

/// An approval record for a workflow stage
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowApproval {
    pub id: String,
    pub stage_instance_id: String,
    pub user_id: String,
    /// Whether this was an approval or rejection
    pub approved: bool,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A transition record between stages
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct WorkflowTransition {
    pub id: String,
    pub instance_id: String,
    pub from_stage_id: Option<String>,
    pub to_stage_id: String,
    pub action: String,
    pub performed_by: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Transition action types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionAction {
    /// Workflow started
    Started,
    /// Advanced to next stage
    Advanced,
    /// Stage approved
    Approved,
    /// Stage rejected
    Rejected,
    /// Workflow completed
    Completed,
    /// Workflow cancelled
    Cancelled,
    /// Workflow put on hold
    OnHold,
    /// Workflow resumed from hold
    Resumed,
    /// Sent back to previous stage
    SentBack,
}

impl std::fmt::Display for TransitionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransitionAction::Started => write!(f, "started"),
            TransitionAction::Advanced => write!(f, "advanced"),
            TransitionAction::Approved => write!(f, "approved"),
            TransitionAction::Rejected => write!(f, "rejected"),
            TransitionAction::Completed => write!(f, "completed"),
            TransitionAction::Cancelled => write!(f, "cancelled"),
            TransitionAction::OnHold => write!(f, "on_hold"),
            TransitionAction::Resumed => write!(f, "resumed"),
            TransitionAction::SentBack => write!(f, "sent_back"),
        }
    }
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to create a new workflow template
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkflowTemplateRequest {
    pub name: String,
    pub description: Option<String>,
    pub stages: Vec<CreateWorkflowStageRequest>,
}

/// Request to create a stage within a template
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkflowStageRequest {
    pub name: String,
    pub description: Option<String>,
    pub stage_type: String,
    pub required_approvals: i32,
    pub approver_role: Option<String>,
    pub approver_user_ids: Option<Vec<String>>,
    pub sla_hours: Option<i32>,
    #[serde(default = "default_true")]
    pub notify_on_enter: bool,
    #[serde(default = "default_true")]
    pub notify_on_sla_breach: bool,
    #[schema(value_type = Object)]
    pub auto_advance_conditions: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// Request to update a workflow template
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateWorkflowTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
    /// If provided, replaces all stages
    pub stages: Option<Vec<CreateWorkflowStageRequest>>,
}

/// Request to start a workflow for a vulnerability
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StartWorkflowRequest {
    pub template_id: String,
    pub notes: Option<String>,
}

/// Request to approve/advance a workflow stage
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApproveWorkflowRequest {
    pub comment: Option<String>,
}

/// Request to reject a workflow stage
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RejectWorkflowRequest {
    pub comment: String,
    /// If true, restart from a specific stage. If false, fail the workflow.
    pub restart_from_stage: Option<String>,
}

/// Request to update workflow status
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UpdateWorkflowRequest {
    pub status: Option<String>,
    pub notes: Option<String>,
}

// ============================================================================
// Response Types
// ============================================================================

/// Workflow template with all stages
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowTemplateWithStages {
    #[serde(flatten)]
    pub template: WorkflowTemplate,
    pub stages: Vec<WorkflowStage>,
}

/// Workflow instance with full details
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowInstanceDetail {
    #[serde(flatten)]
    pub instance: WorkflowInstance,
    pub template: WorkflowTemplate,
    pub current_stage: WorkflowStage,
    pub stage_instances: Vec<StageInstanceWithDetails>,
    pub transitions: Vec<WorkflowTransitionWithUser>,
}

/// Stage instance with stage definition and approvals
#[derive(Debug, Serialize, Deserialize)]
pub struct StageInstanceWithDetails {
    #[serde(flatten)]
    pub stage_instance: WorkflowStageInstance,
    pub stage: WorkflowStage,
    pub approvals: Vec<ApprovalWithUser>,
}

/// Approval with user information (flat structure for sqlx)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApprovalWithUserRow {
    pub id: String,
    pub stage_instance_id: String,
    pub user_id: String,
    pub approved: bool,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
    pub username: String,
}

/// Approval with user information for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalWithUser {
    #[serde(flatten)]
    pub approval: WorkflowApproval,
    pub username: String,
}

impl From<ApprovalWithUserRow> for ApprovalWithUser {
    fn from(row: ApprovalWithUserRow) -> Self {
        ApprovalWithUser {
            approval: WorkflowApproval {
                id: row.id,
                stage_instance_id: row.stage_instance_id,
                user_id: row.user_id,
                approved: row.approved,
                comment: row.comment,
                created_at: row.created_at,
            },
            username: row.username,
        }
    }
}

/// Transition with user information
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct WorkflowTransitionWithUser {
    pub id: String,
    pub instance_id: String,
    pub from_stage_id: Option<String>,
    pub to_stage_id: String,
    pub action: String,
    pub performed_by: String,
    pub username: String,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Summary of pending approvals for a user
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct PendingApproval {
    pub instance_id: String,
    pub stage_instance_id: String,
    pub vulnerability_id: String,
    pub vulnerability_title: String,
    pub severity: String,
    pub stage_name: String,
    pub stage_type: String,
    pub entered_at: DateTime<Utc>,
    pub sla_deadline: Option<DateTime<Utc>>,
    pub sla_breached: bool,
    pub required_approvals: i32,
    pub approvals_received: i32,
}

/// Workflow statistics for dashboard
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkflowStats {
    pub active_workflows: i64,
    pub pending_approvals: i64,
    pub completed_today: i64,
    pub sla_breaches: i64,
    pub avg_completion_hours: Option<f64>,
}

/// Auto-advance condition types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AutoAdvanceCondition {
    /// Advance after a time delay
    TimeDelay { hours: i32 },
    /// Advance when vulnerability status changes
    StatusChange { target_status: String },
    /// Advance based on external webhook
    WebhookTrigger { webhook_id: String },
}
