//! Workflow Executor - handles workflow execution logic
//!
//! This module provides the core logic for:
//! - Starting workflows for vulnerabilities
//! - Advancing through workflow stages
//! - Handling approvals and rejections
//! - Checking SLA compliance
//! - Auto-advancing based on conditions

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use sqlx::SqlitePool;

use super::types::*;
use super::notifications::WorkflowNotifier;
use crate::db::workflows;

/// Workflow executor handles all workflow operations
pub struct WorkflowExecutor {
    pool: SqlitePool,
    notifier: WorkflowNotifier,
}

impl WorkflowExecutor {
    /// Create a new workflow executor
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            notifier: WorkflowNotifier::new(pool.clone()),
            pool,
        }
    }

    /// Start a workflow for a vulnerability
    pub async fn start_workflow(
        &self,
        vulnerability_id: &str,
        template_id: &str,
        user_id: &str,
        notes: Option<String>,
    ) -> Result<WorkflowInstance> {
        // Check if vulnerability already has an active workflow
        if let Some(existing) = workflows::get_active_workflow_for_vulnerability(
            &self.pool,
            vulnerability_id
        ).await? {
            return Err(anyhow::anyhow!(
                "Vulnerability already has an active workflow: {}",
                existing.id
            ));
        }

        // Get template with stages
        let template = workflows::get_template_with_stages(&self.pool, template_id)
            .await
            .context("Failed to get workflow template")?;

        if template.stages.is_empty() {
            return Err(anyhow::anyhow!("Workflow template has no stages"));
        }

        // Get first stage
        let first_stage = template.stages.first().unwrap();

        // Create workflow instance
        let instance = workflows::create_workflow_instance(
            &self.pool,
            template_id,
            vulnerability_id,
            &first_stage.id,
            user_id,
            notes.clone(),
        )
        .await
        .context("Failed to create workflow instance")?;

        // Create stage instance for first stage
        let sla_deadline = first_stage.sla_hours.map(|hours| {
            Utc::now() + Duration::hours(hours as i64)
        });

        workflows::create_stage_instance(
            &self.pool,
            &instance.id,
            &first_stage.id,
            sla_deadline,
        )
        .await
        .context("Failed to create initial stage instance")?;

        // Record transition
        workflows::create_transition(
            &self.pool,
            &instance.id,
            None,
            &first_stage.id,
            &TransitionAction::Started.to_string(),
            user_id,
            notes.as_deref(),
        )
        .await?;

        // Send notification for first stage
        if first_stage.notify_on_enter {
            self.notifier.notify_stage_entered(
                &instance,
                first_stage,
                vulnerability_id,
            ).await?;
        }

        log::info!(
            "Started workflow {} for vulnerability {} using template {}",
            instance.id,
            vulnerability_id,
            template_id
        );

        Ok(instance)
    }

    /// Approve the current stage of a workflow
    pub async fn approve_stage(
        &self,
        instance_id: &str,
        user_id: &str,
        comment: Option<String>,
    ) -> Result<WorkflowInstance> {
        // Get instance with current stage
        let instance = workflows::get_workflow_instance(&self.pool, instance_id)
            .await
            .context("Failed to get workflow instance")?;

        if instance.status != WorkflowStatus::Active.to_string() {
            return Err(anyhow::anyhow!(
                "Cannot approve stage: workflow is not active (status: {})",
                instance.status
            ));
        }

        // Get current stage and stage instance
        let stage = workflows::get_stage(&self.pool, &instance.current_stage_id).await?;
        let stage_instance = workflows::get_active_stage_instance(&self.pool, instance_id, &stage.id)
            .await
            .context("Failed to get stage instance")?;

        // Check if user can approve
        if !self.can_user_approve(&stage, user_id).await? {
            return Err(anyhow::anyhow!(
                "User does not have permission to approve this stage"
            ));
        }

        // Check if user already approved
        let existing_approval = workflows::get_user_approval_for_stage(
            &self.pool,
            &stage_instance.id,
            user_id,
        ).await?;

        if existing_approval.is_some() {
            return Err(anyhow::anyhow!("User has already submitted an approval for this stage"));
        }

        // Record approval
        workflows::create_approval(
            &self.pool,
            &stage_instance.id,
            user_id,
            true,
            comment.clone(),
        )
        .await?;

        // Update approval count
        let new_count = stage_instance.approvals_received + 1;
        workflows::update_stage_approvals(&self.pool, &stage_instance.id, new_count).await?;

        // Check if we have enough approvals to advance
        if new_count >= stage.required_approvals {
            // Advance to next stage
            return self.advance_to_next_stage(&instance, &stage, user_id, comment).await;
        }

        // Record transition for approval
        workflows::create_transition(
            &self.pool,
            instance_id,
            Some(&stage.id),
            &stage.id,
            &TransitionAction::Approved.to_string(),
            user_id,
            comment.as_deref(),
        )
        .await?;

        workflows::get_workflow_instance(&self.pool, instance_id).await
    }

    /// Advance workflow to next stage (for stages with 0 required approvals)
    pub async fn advance_stage(
        &self,
        instance_id: &str,
        user_id: &str,
        comment: Option<String>,
    ) -> Result<WorkflowInstance> {
        let instance = workflows::get_workflow_instance(&self.pool, instance_id)
            .await
            .context("Failed to get workflow instance")?;

        if instance.status != WorkflowStatus::Active.to_string() {
            return Err(anyhow::anyhow!(
                "Cannot advance: workflow is not active (status: {})",
                instance.status
            ));
        }

        let stage = workflows::get_stage(&self.pool, &instance.current_stage_id).await?;

        // For stages with required approvals, use approve_stage instead
        if stage.required_approvals > 0 {
            return Err(anyhow::anyhow!(
                "Stage requires {} approvals. Use approve endpoint instead.",
                stage.required_approvals
            ));
        }

        self.advance_to_next_stage(&instance, &stage, user_id, comment).await
    }

    /// Reject the current stage
    pub async fn reject_stage(
        &self,
        instance_id: &str,
        user_id: &str,
        comment: String,
        restart_from_stage: Option<String>,
    ) -> Result<WorkflowInstance> {
        let instance = workflows::get_workflow_instance(&self.pool, instance_id)
            .await
            .context("Failed to get workflow instance")?;

        if instance.status != WorkflowStatus::Active.to_string() {
            return Err(anyhow::anyhow!(
                "Cannot reject: workflow is not active (status: {})",
                instance.status
            ));
        }

        let current_stage = workflows::get_stage(&self.pool, &instance.current_stage_id).await?;

        // Check if user can approve (rejectors need same permissions)
        if !self.can_user_approve(&current_stage, user_id).await? {
            return Err(anyhow::anyhow!(
                "User does not have permission to reject this stage"
            ));
        }

        // Get stage instance
        let stage_instance = workflows::get_active_stage_instance(&self.pool, instance_id, &current_stage.id)
            .await?;

        // Record rejection
        workflows::create_approval(
            &self.pool,
            &stage_instance.id,
            user_id,
            false,
            Some(comment.clone()),
        )
        .await?;

        // Mark stage as rejected
        workflows::update_stage_status(
            &self.pool,
            &stage_instance.id,
            &StageStatus::Rejected.to_string(),
        )
        .await?;

        if let Some(restart_stage_id) = restart_from_stage {
            // Restart from specific stage
            let restart_stage = workflows::get_stage(&self.pool, &restart_stage_id).await?;

            // Create new stage instance
            let sla_deadline = restart_stage.sla_hours.map(|hours| {
                Utc::now() + Duration::hours(hours as i64)
            });

            workflows::create_stage_instance(
                &self.pool,
                instance_id,
                &restart_stage_id,
                sla_deadline,
            )
            .await?;

            // Update instance to new stage
            workflows::update_workflow_stage(&self.pool, instance_id, &restart_stage_id).await?;

            // Record transition
            workflows::create_transition(
                &self.pool,
                instance_id,
                Some(&current_stage.id),
                &restart_stage_id,
                &TransitionAction::SentBack.to_string(),
                user_id,
                Some(&comment),
            )
            .await?;

            // Notify about restart
            if restart_stage.notify_on_enter {
                self.notifier.notify_stage_entered(
                    &instance,
                    &restart_stage,
                    &instance.vulnerability_id,
                ).await?;
            }
        } else {
            // Fail the workflow
            workflows::update_workflow_status(
                &self.pool,
                instance_id,
                &WorkflowStatus::Rejected.to_string(),
            )
            .await?;

            // Record transition
            workflows::create_transition(
                &self.pool,
                instance_id,
                Some(&current_stage.id),
                &current_stage.id,
                &TransitionAction::Rejected.to_string(),
                user_id,
                Some(&comment),
            )
            .await?;

            // Notify about rejection
            self.notifier.notify_workflow_rejected(&instance, &current_stage, &comment).await?;
        }

        workflows::get_workflow_instance(&self.pool, instance_id).await
    }

    /// Cancel a workflow
    pub async fn cancel_workflow(
        &self,
        instance_id: &str,
        user_id: &str,
        reason: Option<String>,
    ) -> Result<WorkflowInstance> {
        let instance = workflows::get_workflow_instance(&self.pool, instance_id).await?;

        if instance.status != WorkflowStatus::Active.to_string()
            && instance.status != WorkflowStatus::OnHold.to_string() {
            return Err(anyhow::anyhow!(
                "Cannot cancel: workflow is not active or on hold"
            ));
        }

        // Update status
        workflows::update_workflow_status(
            &self.pool,
            instance_id,
            &WorkflowStatus::Cancelled.to_string(),
        )
        .await?;

        // Record transition
        workflows::create_transition(
            &self.pool,
            instance_id,
            Some(&instance.current_stage_id),
            &instance.current_stage_id,
            &TransitionAction::Cancelled.to_string(),
            user_id,
            reason.as_deref(),
        )
        .await?;

        workflows::get_workflow_instance(&self.pool, instance_id).await
    }

    /// Put a workflow on hold
    pub async fn hold_workflow(
        &self,
        instance_id: &str,
        user_id: &str,
        reason: Option<String>,
    ) -> Result<WorkflowInstance> {
        let instance = workflows::get_workflow_instance(&self.pool, instance_id).await?;

        if instance.status != WorkflowStatus::Active.to_string() {
            return Err(anyhow::anyhow!("Cannot hold: workflow is not active"));
        }

        workflows::update_workflow_status(
            &self.pool,
            instance_id,
            &WorkflowStatus::OnHold.to_string(),
        )
        .await?;

        workflows::create_transition(
            &self.pool,
            instance_id,
            Some(&instance.current_stage_id),
            &instance.current_stage_id,
            &TransitionAction::OnHold.to_string(),
            user_id,
            reason.as_deref(),
        )
        .await?;

        workflows::get_workflow_instance(&self.pool, instance_id).await
    }

    /// Resume a workflow from hold
    pub async fn resume_workflow(
        &self,
        instance_id: &str,
        user_id: &str,
    ) -> Result<WorkflowInstance> {
        let instance = workflows::get_workflow_instance(&self.pool, instance_id).await?;

        if instance.status != WorkflowStatus::OnHold.to_string() {
            return Err(anyhow::anyhow!("Cannot resume: workflow is not on hold"));
        }

        workflows::update_workflow_status(
            &self.pool,
            instance_id,
            &WorkflowStatus::Active.to_string(),
        )
        .await?;

        workflows::create_transition(
            &self.pool,
            instance_id,
            Some(&instance.current_stage_id),
            &instance.current_stage_id,
            &TransitionAction::Resumed.to_string(),
            user_id,
            None,
        )
        .await?;

        workflows::get_workflow_instance(&self.pool, instance_id).await
    }

    /// Check and update SLA breaches for active workflows
    pub async fn check_sla_breaches(&self) -> Result<Vec<WorkflowStageInstance>> {
        let breached = workflows::check_and_mark_sla_breaches(&self.pool).await?;

        for stage_instance in &breached {
            // Get stage details for notification
            let stage = workflows::get_stage(&self.pool, &stage_instance.stage_id).await?;
            let instance = workflows::get_workflow_instance(&self.pool, &stage_instance.instance_id).await?;

            if stage.notify_on_sla_breach {
                self.notifier.notify_sla_breach(
                    &instance,
                    &stage,
                    stage_instance.sla_deadline.as_ref(),
                ).await?;
            }
        }

        Ok(breached)
    }

    // ============================================================================
    // Private helper methods
    // ============================================================================

    /// Advance to the next stage in the workflow
    async fn advance_to_next_stage(
        &self,
        instance: &WorkflowInstance,
        current_stage: &WorkflowStage,
        user_id: &str,
        comment: Option<String>,
    ) -> Result<WorkflowInstance> {
        // Mark current stage as completed
        let stage_instance = workflows::get_active_stage_instance(
            &self.pool,
            &instance.id,
            &current_stage.id,
        )
        .await?;

        workflows::update_stage_status(
            &self.pool,
            &stage_instance.id,
            &StageStatus::Completed.to_string(),
        )
        .await?;

        workflows::complete_stage_instance(&self.pool, &stage_instance.id).await?;

        // Get next stage
        let template = workflows::get_template_with_stages(&self.pool, &instance.template_id).await?;
        let next_stage = template
            .stages
            .iter()
            .find(|s| s.stage_order == current_stage.stage_order + 1);

        if let Some(next) = next_stage {
            // Create stage instance for next stage
            let sla_deadline = next.sla_hours.map(|hours| {
                Utc::now() + Duration::hours(hours as i64)
            });

            workflows::create_stage_instance(
                &self.pool,
                &instance.id,
                &next.id,
                sla_deadline,
            )
            .await?;

            // Update instance
            workflows::update_workflow_stage(&self.pool, &instance.id, &next.id).await?;

            // Record transition
            workflows::create_transition(
                &self.pool,
                &instance.id,
                Some(&current_stage.id),
                &next.id,
                &TransitionAction::Advanced.to_string(),
                user_id,
                comment.as_deref(),
            )
            .await?;

            // Notify about new stage
            if next.notify_on_enter {
                self.notifier.notify_stage_entered(
                    instance,
                    next,
                    &instance.vulnerability_id,
                ).await?;
            }
        } else {
            // No more stages - workflow completed
            workflows::update_workflow_status(
                &self.pool,
                &instance.id,
                &WorkflowStatus::Completed.to_string(),
            )
            .await?;

            workflows::complete_workflow(&self.pool, &instance.id).await?;

            // Record transition
            workflows::create_transition(
                &self.pool,
                &instance.id,
                Some(&current_stage.id),
                &current_stage.id,
                &TransitionAction::Completed.to_string(),
                user_id,
                comment.as_deref(),
            )
            .await?;

            // Notify about completion
            self.notifier.notify_workflow_completed(instance).await?;
        }

        workflows::get_workflow_instance(&self.pool, &instance.id).await
    }

    /// Check if a user can approve a stage
    async fn can_user_approve(&self, stage: &WorkflowStage, user_id: &str) -> Result<bool> {
        // Check specific user IDs first
        if let Some(user_ids_json) = &stage.approver_user_ids {
            let user_ids: Vec<String> = serde_json::from_str(user_ids_json)?;
            if user_ids.contains(&user_id.to_string()) {
                return Ok(true);
            }
            // If specific users are set, only they can approve
            if !user_ids.is_empty() {
                return Ok(false);
            }
        }

        // Check role
        if let Some(role) = &stage.approver_role {
            let user_roles = crate::db::get_user_roles(&self.pool, user_id).await?;
            return Ok(user_roles.iter().any(|r| &r.name == role));
        }

        // No restrictions - any user can approve
        Ok(true)
    }
}
