//! Workflow Engine for Remediation Workflows
//!
//! This module provides configurable approval chains for vulnerability remediation:
//! - Workflow templates with multiple stages
//! - Configurable approval requirements per stage
//! - Automatic transitions based on conditions
//! - SLA tracking per workflow stage
//! - Notifications for pending approvals
//! - Complete audit trail for all workflow actions

pub mod types;
pub mod executor;
pub mod notifications;

pub use types::*;
pub use executor::WorkflowExecutor;
pub use notifications::WorkflowNotifier;

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialize default workflow templates if they don't exist
pub async fn seed_default_templates(pool: &SqlitePool) -> Result<()> {
    use crate::db::workflows;

    // Check if system templates already exist
    let existing = workflows::get_system_templates(pool).await?;
    if !existing.is_empty() {
        log::info!("Workflow templates already seeded ({} templates)", existing.len());
        return Ok(());
    }

    log::info!("Seeding default workflow templates...");

    // Simple workflow: Assign → Fix → Verify → Close
    let simple_template = CreateWorkflowTemplateRequest {
        name: "Simple".to_string(),
        description: Some("Basic remediation workflow with minimal stages".to_string()),
        stages: vec![
            CreateWorkflowStageRequest {
                name: "Assignment".to_string(),
                description: Some("Assign the vulnerability to a team member".to_string()),
                stage_type: "assignment".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Fix".to_string(),
                description: Some("Implement the fix for the vulnerability".to_string()),
                stage_type: "work".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(72),
                notify_on_enter: false,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Verify".to_string(),
                description: Some("Verify the fix resolves the vulnerability".to_string()),
                stage_type: "verification".to_string(),
                required_approvals: 1,
                approver_role: Some("admin".to_string()),
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Close".to_string(),
                description: Some("Close the vulnerability as remediated".to_string()),
                stage_type: "closure".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: None,
                notify_on_enter: false,
                notify_on_sla_breach: false,
                auto_advance_conditions: None,
            },
        ],
    };

    // Standard workflow: Assign → Fix → Review → Verify → Close
    let standard_template = CreateWorkflowTemplateRequest {
        name: "Standard".to_string(),
        description: Some("Standard remediation workflow with code review stage".to_string()),
        stages: vec![
            CreateWorkflowStageRequest {
                name: "Assignment".to_string(),
                description: Some("Assign the vulnerability to a team member".to_string()),
                stage_type: "assignment".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Fix".to_string(),
                description: Some("Implement the fix for the vulnerability".to_string()),
                stage_type: "work".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(48),
                notify_on_enter: false,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Code Review".to_string(),
                description: Some("Peer review of the fix implementation".to_string()),
                stage_type: "review".to_string(),
                required_approvals: 1,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Security Verification".to_string(),
                description: Some("Security team verifies the fix".to_string()),
                stage_type: "verification".to_string(),
                required_approvals: 1,
                approver_role: Some("admin".to_string()),
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Close".to_string(),
                description: Some("Close the vulnerability as remediated".to_string()),
                stage_type: "closure".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: None,
                notify_on_enter: false,
                notify_on_sla_breach: false,
                auto_advance_conditions: None,
            },
        ],
    };

    // Enterprise workflow: Assign → Fix → Peer Review → Security Review → CAB Approval → Deploy → Verify → Close
    let enterprise_template = CreateWorkflowTemplateRequest {
        name: "Enterprise".to_string(),
        description: Some("Enterprise remediation workflow with CAB approval and deployment stages".to_string()),
        stages: vec![
            CreateWorkflowStageRequest {
                name: "Assignment".to_string(),
                description: Some("Assign the vulnerability to the appropriate team".to_string()),
                stage_type: "assignment".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(8),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Fix Development".to_string(),
                description: Some("Develop and test the fix for the vulnerability".to_string()),
                stage_type: "work".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(72),
                notify_on_enter: false,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Peer Review".to_string(),
                description: Some("Code review by development peers".to_string()),
                stage_type: "review".to_string(),
                required_approvals: 2,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Security Review".to_string(),
                description: Some("Security team reviews the fix for completeness".to_string()),
                stage_type: "review".to_string(),
                required_approvals: 1,
                approver_role: Some("admin".to_string()),
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "CAB Approval".to_string(),
                description: Some("Change Advisory Board approval for production deployment".to_string()),
                stage_type: "cab_approval".to_string(),
                required_approvals: 1,
                approver_role: Some("admin".to_string()),
                approver_user_ids: None,
                sla_hours: Some(48),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Deployment".to_string(),
                description: Some("Deploy the fix to production".to_string()),
                stage_type: "deployment".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Verification".to_string(),
                description: Some("Verify the fix in production environment".to_string()),
                stage_type: "verification".to_string(),
                required_approvals: 1,
                approver_role: Some("admin".to_string()),
                approver_user_ids: None,
                sla_hours: Some(24),
                notify_on_enter: true,
                notify_on_sla_breach: true,
                auto_advance_conditions: None,
            },
            CreateWorkflowStageRequest {
                name: "Close".to_string(),
                description: Some("Close the vulnerability as remediated".to_string()),
                stage_type: "closure".to_string(),
                required_approvals: 0,
                approver_role: None,
                approver_user_ids: None,
                sla_hours: None,
                notify_on_enter: false,
                notify_on_sla_breach: false,
                auto_advance_conditions: None,
            },
        ],
    };

    // Create templates
    workflows::create_system_template(pool, simple_template).await?;
    workflows::create_system_template(pool, standard_template).await?;
    workflows::create_system_template(pool, enterprise_template).await?;

    log::info!("Default workflow templates seeded successfully");
    Ok(())
}
