//! Database operations for remediation workflows
//!
//! This module provides database operations for:
//! - Workflow templates and stages
//! - Workflow instances
//! - Stage instances and approvals
//! - Transitions and audit trail

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::workflows::types::*;

// ============================================================================
// Template Operations
// ============================================================================

/// Get all workflow templates
pub async fn get_all_templates(pool: &SqlitePool) -> Result<Vec<WorkflowTemplate>> {
    let templates = sqlx::query_as::<_, WorkflowTemplate>(
        "SELECT * FROM workflow_templates WHERE is_active = 1 ORDER BY name"
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get system-defined templates
pub async fn get_system_templates(pool: &SqlitePool) -> Result<Vec<WorkflowTemplate>> {
    let templates = sqlx::query_as::<_, WorkflowTemplate>(
        "SELECT * FROM workflow_templates WHERE is_system = 1 AND is_active = 1 ORDER BY name"
    )
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get user-defined templates
pub async fn get_user_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<WorkflowTemplate>> {
    let templates = sqlx::query_as::<_, WorkflowTemplate>(
        "SELECT * FROM workflow_templates WHERE created_by = ?1 AND is_active = 1 ORDER BY name"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get a template by ID
pub async fn get_template(pool: &SqlitePool, template_id: &str) -> Result<WorkflowTemplate> {
    let template = sqlx::query_as::<_, WorkflowTemplate>(
        "SELECT * FROM workflow_templates WHERE id = ?1"
    )
    .bind(template_id)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get a template with all its stages
pub async fn get_template_with_stages(
    pool: &SqlitePool,
    template_id: &str,
) -> Result<WorkflowTemplateWithStages> {
    let template = get_template(pool, template_id).await?;

    let stages = sqlx::query_as::<_, WorkflowStage>(
        "SELECT * FROM workflow_stages WHERE template_id = ?1 ORDER BY stage_order"
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    Ok(WorkflowTemplateWithStages { template, stages })
}

/// Create a system workflow template
pub async fn create_system_template(
    pool: &SqlitePool,
    request: CreateWorkflowTemplateRequest,
) -> Result<WorkflowTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Create template
    let template = sqlx::query_as::<_, WorkflowTemplate>(
        r#"
        INSERT INTO workflow_templates
        (id, name, description, is_system, created_by, created_at, updated_at, is_active)
        VALUES (?1, ?2, ?3, 1, NULL, ?4, ?5, 1)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    // Create stages
    for (order, stage_request) in request.stages.into_iter().enumerate() {
        create_stage(pool, &id, order as i32, stage_request).await?;
    }

    Ok(template)
}

/// Create a user workflow template
pub async fn create_user_template(
    pool: &SqlitePool,
    user_id: &str,
    request: CreateWorkflowTemplateRequest,
) -> Result<WorkflowTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Create template
    let template = sqlx::query_as::<_, WorkflowTemplate>(
        r#"
        INSERT INTO workflow_templates
        (id, name, description, is_system, created_by, created_at, updated_at, is_active)
        VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, 1)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    // Create stages
    for (order, stage_request) in request.stages.into_iter().enumerate() {
        create_stage(pool, &id, order as i32, stage_request).await?;
    }

    Ok(template)
}

/// Update a workflow template
pub async fn update_template(
    pool: &SqlitePool,
    template_id: &str,
    request: UpdateWorkflowTemplateRequest,
) -> Result<WorkflowTemplate> {
    let now = Utc::now();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?1".to_string()];
    let mut param_idx = 2;

    if request.name.is_some() {
        updates.push(format!("name = ?{}", param_idx));
        param_idx += 1;
    }
    if request.description.is_some() {
        updates.push(format!("description = ?{}", param_idx));
        param_idx += 1;
    }
    if request.is_active.is_some() {
        updates.push(format!("is_active = ?{}", param_idx));
        param_idx += 1;
    }

    let query = format!(
        "UPDATE workflow_templates SET {} WHERE id = ?{} RETURNING *",
        updates.join(", "),
        param_idx
    );

    let mut q = sqlx::query_as::<_, WorkflowTemplate>(&query).bind(now);

    if let Some(name) = &request.name {
        q = q.bind(name);
    }
    if let Some(desc) = &request.description {
        q = q.bind(desc);
    }
    if let Some(active) = request.is_active {
        q = q.bind(active);
    }

    let template = q.bind(template_id).fetch_one(pool).await?;

    // If stages are provided, replace them
    if let Some(stages) = request.stages {
        // Delete existing stages
        sqlx::query("DELETE FROM workflow_stages WHERE template_id = ?1")
            .bind(template_id)
            .execute(pool)
            .await?;

        // Create new stages
        for (order, stage_request) in stages.into_iter().enumerate() {
            create_stage(pool, template_id, order as i32, stage_request).await?;
        }
    }

    Ok(template)
}

/// Delete a workflow template (soft delete by setting is_active = false)
pub async fn delete_template(pool: &SqlitePool, template_id: &str) -> Result<()> {
    sqlx::query("UPDATE workflow_templates SET is_active = 0, updated_at = ?1 WHERE id = ?2")
        .bind(Utc::now())
        .bind(template_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Stage Operations
// ============================================================================

/// Create a workflow stage
pub async fn create_stage(
    pool: &SqlitePool,
    template_id: &str,
    stage_order: i32,
    request: CreateWorkflowStageRequest,
) -> Result<WorkflowStage> {
    let id = Uuid::new_v4().to_string();

    let approver_user_ids = request.approver_user_ids
        .map(|ids| serde_json::to_string(&ids).unwrap_or_default());

    let auto_advance = request.auto_advance_conditions
        .map(|c| serde_json::to_string(&c).unwrap_or_default());

    let stage = sqlx::query_as::<_, WorkflowStage>(
        r#"
        INSERT INTO workflow_stages
        (id, template_id, name, description, stage_order, stage_type,
         required_approvals, approver_role, approver_user_ids, sla_hours,
         notify_on_enter, notify_on_sla_breach, auto_advance_conditions)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(template_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(stage_order)
    .bind(&request.stage_type)
    .bind(request.required_approvals)
    .bind(&request.approver_role)
    .bind(&approver_user_ids)
    .bind(request.sla_hours)
    .bind(request.notify_on_enter)
    .bind(request.notify_on_sla_breach)
    .bind(&auto_advance)
    .fetch_one(pool)
    .await?;

    Ok(stage)
}

/// Get a stage by ID
pub async fn get_stage(pool: &SqlitePool, stage_id: &str) -> Result<WorkflowStage> {
    let stage = sqlx::query_as::<_, WorkflowStage>(
        "SELECT * FROM workflow_stages WHERE id = ?1"
    )
    .bind(stage_id)
    .fetch_one(pool)
    .await?;

    Ok(stage)
}

/// Get stages for a template
pub async fn get_stages_for_template(
    pool: &SqlitePool,
    template_id: &str,
) -> Result<Vec<WorkflowStage>> {
    let stages = sqlx::query_as::<_, WorkflowStage>(
        "SELECT * FROM workflow_stages WHERE template_id = ?1 ORDER BY stage_order"
    )
    .bind(template_id)
    .fetch_all(pool)
    .await?;

    Ok(stages)
}

// ============================================================================
// Workflow Instance Operations
// ============================================================================

/// Create a workflow instance
pub async fn create_workflow_instance(
    pool: &SqlitePool,
    template_id: &str,
    vulnerability_id: &str,
    initial_stage_id: &str,
    started_by: &str,
    notes: Option<String>,
) -> Result<WorkflowInstance> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let instance = sqlx::query_as::<_, WorkflowInstance>(
        r#"
        INSERT INTO workflow_instances
        (id, template_id, vulnerability_id, current_stage_id, status, started_by, started_at, notes)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(template_id)
    .bind(vulnerability_id)
    .bind(initial_stage_id)
    .bind(WorkflowStatus::Active.to_string())
    .bind(started_by)
    .bind(now)
    .bind(notes)
    .fetch_one(pool)
    .await?;

    Ok(instance)
}

/// Get a workflow instance by ID
pub async fn get_workflow_instance(pool: &SqlitePool, instance_id: &str) -> Result<WorkflowInstance> {
    let instance = sqlx::query_as::<_, WorkflowInstance>(
        "SELECT * FROM workflow_instances WHERE id = ?1"
    )
    .bind(instance_id)
    .fetch_one(pool)
    .await?;

    Ok(instance)
}

/// Get active workflow for a vulnerability
pub async fn get_active_workflow_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Option<WorkflowInstance>> {
    let instance = sqlx::query_as::<_, WorkflowInstance>(
        "SELECT * FROM workflow_instances WHERE vulnerability_id = ?1 AND status = 'active'"
    )
    .bind(vulnerability_id)
    .fetch_optional(pool)
    .await?;

    Ok(instance)
}

/// Get all workflows for a vulnerability
pub async fn get_workflows_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<WorkflowInstance>> {
    let instances = sqlx::query_as::<_, WorkflowInstance>(
        "SELECT * FROM workflow_instances WHERE vulnerability_id = ?1 ORDER BY started_at DESC"
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(instances)
}

/// Get all active workflow instances
pub async fn get_active_workflows(pool: &SqlitePool) -> Result<Vec<WorkflowInstance>> {
    let instances = sqlx::query_as::<_, WorkflowInstance>(
        "SELECT * FROM workflow_instances WHERE status = 'active' ORDER BY started_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(instances)
}

/// Get workflow instances by status
pub async fn get_workflows_by_status(
    pool: &SqlitePool,
    status: &str,
) -> Result<Vec<WorkflowInstance>> {
    let instances = sqlx::query_as::<_, WorkflowInstance>(
        "SELECT * FROM workflow_instances WHERE status = ?1 ORDER BY started_at DESC"
    )
    .bind(status)
    .fetch_all(pool)
    .await?;

    Ok(instances)
}

/// Update workflow status
pub async fn update_workflow_status(
    pool: &SqlitePool,
    instance_id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query("UPDATE workflow_instances SET status = ?1 WHERE id = ?2")
        .bind(status)
        .bind(instance_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update workflow current stage
pub async fn update_workflow_stage(
    pool: &SqlitePool,
    instance_id: &str,
    stage_id: &str,
) -> Result<()> {
    sqlx::query("UPDATE workflow_instances SET current_stage_id = ?1 WHERE id = ?2")
        .bind(stage_id)
        .bind(instance_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Complete a workflow
pub async fn complete_workflow(pool: &SqlitePool, instance_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE workflow_instances SET status = 'completed', completed_at = ?1 WHERE id = ?2"
    )
    .bind(Utc::now())
    .bind(instance_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Stage Instance Operations
// ============================================================================

/// Create a stage instance
pub async fn create_stage_instance(
    pool: &SqlitePool,
    instance_id: &str,
    stage_id: &str,
    sla_deadline: Option<DateTime<Utc>>,
) -> Result<WorkflowStageInstance> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let stage_instance = sqlx::query_as::<_, WorkflowStageInstance>(
        r#"
        INSERT INTO workflow_stage_instances
        (id, instance_id, stage_id, status, entered_at, sla_deadline, sla_breached, approvals_received)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(instance_id)
    .bind(stage_id)
    .bind(StageStatus::Active.to_string())
    .bind(now)
    .bind(sla_deadline)
    .fetch_one(pool)
    .await?;

    Ok(stage_instance)
}

/// Get active stage instance for a workflow
pub async fn get_active_stage_instance(
    pool: &SqlitePool,
    instance_id: &str,
    stage_id: &str,
) -> Result<WorkflowStageInstance> {
    let stage_instance = sqlx::query_as::<_, WorkflowStageInstance>(
        "SELECT * FROM workflow_stage_instances WHERE instance_id = ?1 AND stage_id = ?2 AND status = 'active'"
    )
    .bind(instance_id)
    .bind(stage_id)
    .fetch_one(pool)
    .await?;

    Ok(stage_instance)
}

/// Get all stage instances for a workflow
pub async fn get_stage_instances_for_workflow(
    pool: &SqlitePool,
    instance_id: &str,
) -> Result<Vec<WorkflowStageInstance>> {
    let instances = sqlx::query_as::<_, WorkflowStageInstance>(
        "SELECT * FROM workflow_stage_instances WHERE instance_id = ?1 ORDER BY entered_at"
    )
    .bind(instance_id)
    .fetch_all(pool)
    .await?;

    Ok(instances)
}

/// Update stage instance status
pub async fn update_stage_status(
    pool: &SqlitePool,
    stage_instance_id: &str,
    status: &str,
) -> Result<()> {
    sqlx::query("UPDATE workflow_stage_instances SET status = ?1 WHERE id = ?2")
        .bind(status)
        .bind(stage_instance_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update stage approval count
pub async fn update_stage_approvals(
    pool: &SqlitePool,
    stage_instance_id: &str,
    count: i32,
) -> Result<()> {
    sqlx::query("UPDATE workflow_stage_instances SET approvals_received = ?1 WHERE id = ?2")
        .bind(count)
        .bind(stage_instance_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Complete a stage instance
pub async fn complete_stage_instance(pool: &SqlitePool, stage_instance_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE workflow_stage_instances SET status = 'completed', completed_at = ?1 WHERE id = ?2"
    )
    .bind(Utc::now())
    .bind(stage_instance_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check and mark SLA breaches
pub async fn check_and_mark_sla_breaches(pool: &SqlitePool) -> Result<Vec<WorkflowStageInstance>> {
    let now = Utc::now();

    // Get stages that have breached SLA but not yet marked
    let breached = sqlx::query_as::<_, WorkflowStageInstance>(
        r#"
        SELECT * FROM workflow_stage_instances
        WHERE status = 'active'
          AND sla_deadline IS NOT NULL
          AND sla_breached = 0
          AND sla_deadline < ?1
        "#,
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    // Mark them as breached
    for instance in &breached {
        sqlx::query("UPDATE workflow_stage_instances SET sla_breached = 1 WHERE id = ?1")
            .bind(&instance.id)
            .execute(pool)
            .await?;
    }

    Ok(breached)
}

// ============================================================================
// Approval Operations
// ============================================================================

/// Create an approval record
pub async fn create_approval(
    pool: &SqlitePool,
    stage_instance_id: &str,
    user_id: &str,
    approved: bool,
    comment: Option<String>,
) -> Result<WorkflowApproval> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let approval = sqlx::query_as::<_, WorkflowApproval>(
        r#"
        INSERT INTO workflow_approvals
        (id, stage_instance_id, user_id, approved, comment, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(stage_instance_id)
    .bind(user_id)
    .bind(approved)
    .bind(comment)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(approval)
}

/// Get user's approval for a stage
pub async fn get_user_approval_for_stage(
    pool: &SqlitePool,
    stage_instance_id: &str,
    user_id: &str,
) -> Result<Option<WorkflowApproval>> {
    let approval = sqlx::query_as::<_, WorkflowApproval>(
        "SELECT * FROM workflow_approvals WHERE stage_instance_id = ?1 AND user_id = ?2"
    )
    .bind(stage_instance_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(approval)
}

/// Get all approvals for a stage
pub async fn get_approvals_for_stage(
    pool: &SqlitePool,
    stage_instance_id: &str,
) -> Result<Vec<WorkflowApproval>> {
    let approvals = sqlx::query_as::<_, WorkflowApproval>(
        "SELECT * FROM workflow_approvals WHERE stage_instance_id = ?1 ORDER BY created_at"
    )
    .bind(stage_instance_id)
    .fetch_all(pool)
    .await?;

    Ok(approvals)
}

/// Get approvals with user info
pub async fn get_approvals_with_users(
    pool: &SqlitePool,
    stage_instance_id: &str,
) -> Result<Vec<ApprovalWithUser>> {
    let rows = sqlx::query_as::<_, ApprovalWithUserRow>(
        r#"
        SELECT wa.id, wa.stage_instance_id, wa.user_id, wa.approved, wa.comment, wa.created_at, u.username
        FROM workflow_approvals wa
        JOIN users u ON wa.user_id = u.id
        WHERE wa.stage_instance_id = ?1
        ORDER BY wa.created_at
        "#,
    )
    .bind(stage_instance_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(ApprovalWithUser::from).collect())
}

// ============================================================================
// Transition Operations
// ============================================================================

/// Create a transition record
pub async fn create_transition(
    pool: &SqlitePool,
    instance_id: &str,
    from_stage_id: Option<&str>,
    to_stage_id: &str,
    action: &str,
    performed_by: &str,
    comment: Option<&str>,
) -> Result<WorkflowTransition> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let transition = sqlx::query_as::<_, WorkflowTransition>(
        r#"
        INSERT INTO workflow_transitions
        (id, instance_id, from_stage_id, to_stage_id, action, performed_by, comment, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(instance_id)
    .bind(from_stage_id)
    .bind(to_stage_id)
    .bind(action)
    .bind(performed_by)
    .bind(comment)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(transition)
}

/// Get transitions for a workflow instance
pub async fn get_transitions_for_workflow(
    pool: &SqlitePool,
    instance_id: &str,
) -> Result<Vec<WorkflowTransition>> {
    let transitions = sqlx::query_as::<_, WorkflowTransition>(
        "SELECT * FROM workflow_transitions WHERE instance_id = ?1 ORDER BY created_at"
    )
    .bind(instance_id)
    .fetch_all(pool)
    .await?;

    Ok(transitions)
}

/// Get transitions with user info
pub async fn get_transitions_with_users(
    pool: &SqlitePool,
    instance_id: &str,
) -> Result<Vec<WorkflowTransitionWithUser>> {
    let transitions = sqlx::query_as::<_, WorkflowTransitionWithUser>(
        r#"
        SELECT wt.*, u.username
        FROM workflow_transitions wt
        JOIN users u ON wt.performed_by = u.id
        WHERE wt.instance_id = ?1
        ORDER BY wt.created_at
        "#,
    )
    .bind(instance_id)
    .fetch_all(pool)
    .await?;

    Ok(transitions)
}

// ============================================================================
// Pending Approvals and Statistics
// ============================================================================

/// Get pending approvals for a user
pub async fn get_pending_approvals_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<PendingApproval>> {
    // This query finds stages where:
    // 1. The workflow is active
    // 2. The stage is active
    // 3. The user hasn't already approved
    // 4. The user has permission to approve (role-based or specific user list)
    let pending = sqlx::query_as::<_, PendingApproval>(
        r#"
        SELECT
            wi.id as instance_id,
            wsi.id as stage_instance_id,
            wi.vulnerability_id,
            vt.vulnerability_id as vulnerability_title,
            vt.severity,
            ws.name as stage_name,
            ws.stage_type,
            wsi.entered_at,
            wsi.sla_deadline,
            wsi.sla_breached,
            ws.required_approvals,
            wsi.approvals_received
        FROM workflow_instances wi
        JOIN workflow_stage_instances wsi ON wi.id = wsi.instance_id AND wi.current_stage_id = wsi.stage_id
        JOIN workflow_stages ws ON wsi.stage_id = ws.id
        JOIN vulnerability_tracking vt ON wi.vulnerability_id = vt.id
        LEFT JOIN workflow_approvals wa ON wsi.id = wa.stage_instance_id AND wa.user_id = ?1
        LEFT JOIN user_roles ur ON ur.user_id = ?1 AND ur.role_id = ws.approver_role
        WHERE wi.status = 'active'
          AND wsi.status = 'active'
          AND wa.id IS NULL
          AND (
            ws.approver_role IS NULL
            OR ur.role_id IS NOT NULL
            OR ws.approver_user_ids LIKE '%' || ?1 || '%'
          )
        ORDER BY wsi.entered_at
        "#,
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(pending)
}

/// Get workflow statistics
pub async fn get_workflow_stats(pool: &SqlitePool) -> Result<WorkflowStats> {
    let active: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workflow_instances WHERE status = 'active'"
    )
    .fetch_one(pool)
    .await?;

    let pending: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT wsi.id)
        FROM workflow_stage_instances wsi
        JOIN workflow_instances wi ON wsi.instance_id = wi.id
        JOIN workflow_stages ws ON wsi.stage_id = ws.id
        WHERE wi.status = 'active'
          AND wsi.status = 'active'
          AND ws.required_approvals > 0
        "#
    )
    .fetch_one(pool)
    .await?;

    let completed_today: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM workflow_instances WHERE status = 'completed' AND date(completed_at) = date('now')"
    )
    .fetch_one(pool)
    .await?;

    let sla_breaches: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM workflow_stage_instances wsi
        JOIN workflow_instances wi ON wsi.instance_id = wi.id
        WHERE wi.status = 'active'
          AND wsi.sla_breached = 1
        "#
    )
    .fetch_one(pool)
    .await?;

    // Calculate average completion time in hours
    let avg_completion: Option<(f64,)> = sqlx::query_as(
        r#"
        SELECT AVG((julianday(completed_at) - julianday(started_at)) * 24)
        FROM workflow_instances
        WHERE status = 'completed'
          AND completed_at IS NOT NULL
        "#
    )
    .fetch_optional(pool)
    .await?;

    Ok(WorkflowStats {
        active_workflows: active.0,
        pending_approvals: pending.0,
        completed_today: completed_today.0,
        sla_breaches: sla_breaches.0,
        avg_completion_hours: avg_completion.map(|r| r.0),
    })
}

// ============================================================================
// Full Detail Queries
// ============================================================================

/// Get workflow instance with full details
pub async fn get_workflow_instance_detail(
    pool: &SqlitePool,
    instance_id: &str,
) -> Result<WorkflowInstanceDetail> {
    let instance = get_workflow_instance(pool, instance_id).await?;
    let template = get_template(pool, &instance.template_id).await?;
    let current_stage = get_stage(pool, &instance.current_stage_id).await?;
    let stage_instances = get_stage_instances_for_workflow(pool, instance_id).await?;
    let transitions = get_transitions_with_users(pool, instance_id).await?;

    // Get stage details and approvals for each stage instance
    let mut stage_details = Vec::new();
    for si in stage_instances {
        let stage = get_stage(pool, &si.stage_id).await?;
        let approvals = get_approvals_with_users(pool, &si.id).await?;
        stage_details.push(StageInstanceWithDetails {
            stage_instance: si,
            stage,
            approvals,
        });
    }

    Ok(WorkflowInstanceDetail {
        instance,
        template,
        current_stage,
        stage_instances: stage_details,
        transitions,
    })
}
