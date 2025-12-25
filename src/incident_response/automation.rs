//! SOAR-lite Automation Module
//!
//! Provides response automation capabilities:
//! - Response playbooks (containment, eradication actions)
//! - Automated actions: block IP, disable account, isolate host (mock/documented)
//! - Action approval workflow
//! - Action audit logging

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

// ============================================================================
// Playbook Management
// ============================================================================

/// Create a new response playbook
pub async fn create_playbook(
    pool: &SqlitePool,
    user_id: &str,
    request: CreatePlaybookRequest,
) -> Result<ResponsePlaybook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let trigger_conditions = request
        .trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?;
    let steps_json = serde_json::to_string(&request.steps)?;

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        INSERT INTO response_playbooks
        (id, name, description, trigger_conditions, steps_json, is_builtin, user_id, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&trigger_conditions)
    .bind(&steps_json)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Create a built-in playbook
pub async fn create_builtin_playbook(
    pool: &SqlitePool,
    name: &str,
    description: Option<&str>,
    trigger_conditions: Option<serde_json::Value>,
    steps: Vec<PlaybookStep>,
) -> Result<ResponsePlaybook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let trigger_str = trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?;
    let steps_json = serde_json::to_string(&steps)?;

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        INSERT INTO response_playbooks
        (id, name, description, trigger_conditions, steps_json, is_builtin, user_id, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 1, NULL, ?6, ?7)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(&trigger_str)
    .bind(&steps_json)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Get a playbook by ID
pub async fn get_playbook(pool: &SqlitePool, playbook_id: &str) -> Result<ResponsePlaybook> {
    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE id = ?1"
    )
    .bind(playbook_id)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// List all playbooks
pub async fn list_playbooks(pool: &SqlitePool) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks ORDER BY is_builtin DESC, name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// List built-in playbooks
pub async fn list_builtin_playbooks(pool: &SqlitePool) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE is_builtin = 1 ORDER BY name ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// List user-created playbooks
pub async fn list_user_playbooks(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ResponsePlaybook>> {
    let playbooks = sqlx::query_as::<_, ResponsePlaybook>(
        "SELECT * FROM response_playbooks WHERE user_id = ?1 ORDER BY name ASC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(playbooks)
}

/// Update a playbook
pub async fn update_playbook(
    pool: &SqlitePool,
    playbook_id: &str,
    request: UpdatePlaybookRequest,
) -> Result<ResponsePlaybook> {
    let now = Utc::now();
    let existing = get_playbook(pool, playbook_id).await?;

    // Cannot update built-in playbooks
    if existing.is_builtin {
        return Err(anyhow::anyhow!("Cannot update built-in playbooks"));
    }

    let name = request.name.unwrap_or(existing.name);
    let description = request.description.or(existing.description);
    let trigger_conditions = request
        .trigger_conditions
        .map(|v| serde_json::to_string(&v))
        .transpose()?
        .or(existing.trigger_conditions);
    let steps_json = request
        .steps
        .map(|s| serde_json::to_string(&s))
        .transpose()?
        .unwrap_or(existing.steps_json);

    let playbook = sqlx::query_as::<_, ResponsePlaybook>(
        r#"
        UPDATE response_playbooks
        SET name = ?1, description = ?2, trigger_conditions = ?3, steps_json = ?4, updated_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(&name)
    .bind(&description)
    .bind(&trigger_conditions)
    .bind(&steps_json)
    .bind(now)
    .bind(playbook_id)
    .fetch_one(pool)
    .await?;

    Ok(playbook)
}

/// Delete a playbook
pub async fn delete_playbook(pool: &SqlitePool, playbook_id: &str) -> Result<()> {
    let existing = get_playbook(pool, playbook_id).await?;

    if existing.is_builtin {
        return Err(anyhow::anyhow!("Cannot delete built-in playbooks"));
    }

    sqlx::query("DELETE FROM response_playbooks WHERE id = ?1")
        .bind(playbook_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get playbook steps parsed from JSON
pub fn get_playbook_steps(playbook: &ResponsePlaybook) -> Result<Vec<PlaybookStep>> {
    let steps: Vec<PlaybookStep> = serde_json::from_str(&playbook.steps_json)?;
    Ok(steps)
}

// ============================================================================
// Response Actions
// ============================================================================

/// Create a response action
pub async fn create_action(
    pool: &SqlitePool,
    incident_id: &str,
    created_by: &str,
    request: ExecuteActionRequest,
) -> Result<ResponseAction> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate action type
    let _: ResponseActionType = request.action_type.parse()?;

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        INSERT INTO response_actions
        (id, incident_id, playbook_id, action_type, target, status, created_at, created_by)
        VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(incident_id)
    .bind(&request.playbook_id)
    .bind(&request.action_type)
    .bind(&request.target)
    .bind(now)
    .bind(created_by)
    .fetch_one(pool)
    .await?;

    // Create audit log entry
    log_action_event(pool, &id, "created", Some(serde_json::json!({
        "action_type": request.action_type,
        "target": request.target,
        "created_by": created_by
    }))).await?;

    Ok(action)
}

/// Get an action by ID
pub async fn get_action(pool: &SqlitePool, action_id: &str) -> Result<ResponseAction> {
    let action = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE id = ?1"
    )
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    Ok(action)
}

/// Get action with details
pub async fn get_action_with_details(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<ResponseActionWithDetails> {
    let action = get_action(pool, action_id).await?;

    let approver_name: Option<String> = if let Some(ref approver_id) = action.approved_by {
        sqlx::query_scalar("SELECT username FROM users WHERE id = ?1")
            .bind(approver_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    let creator_name: Option<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE id = ?1"
    )
    .bind(&action.created_by)
    .fetch_optional(pool)
    .await?;

    let playbook_name: Option<String> = if let Some(ref playbook_id) = action.playbook_id {
        sqlx::query_scalar("SELECT name FROM response_playbooks WHERE id = ?1")
            .bind(playbook_id)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    Ok(ResponseActionWithDetails {
        action,
        approver_name,
        creator_name,
        playbook_name,
    })
}

/// List actions for an incident
pub async fn list_incident_actions(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<ResponseAction>> {
    let actions = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE incident_id = ?1 ORDER BY created_at DESC"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(actions)
}

/// List pending actions requiring approval
pub async fn list_pending_actions(pool: &SqlitePool) -> Result<Vec<ResponseAction>> {
    let actions = sqlx::query_as::<_, ResponseAction>(
        "SELECT * FROM response_actions WHERE status = 'pending' ORDER BY created_at ASC"
    )
    .fetch_all(pool)
    .await?;

    Ok(actions)
}

/// Approve an action
pub async fn approve_action(
    pool: &SqlitePool,
    action_id: &str,
    approver_id: &str,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" {
        return Err(anyhow::anyhow!("Action is not in pending status"));
    }

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'approved', approved_by = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(approver_id)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "approved", Some(serde_json::json!({
        "approved_by": approver_id
    }))).await?;

    Ok(action)
}

/// Reject an action
pub async fn reject_action(
    pool: &SqlitePool,
    action_id: &str,
    rejector_id: &str,
    notes: Option<&str>,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" {
        return Err(anyhow::anyhow!("Action is not in pending status"));
    }

    let result = notes.map(|n| format!("Rejected: {}", n));

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'rejected', result = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "rejected", Some(serde_json::json!({
        "rejected_by": rejector_id,
        "notes": notes
    }))).await?;

    Ok(action)
}

/// Execute an action (mock implementation - logs intent)
pub async fn execute_action(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "approved" {
        return Err(anyhow::anyhow!("Action must be approved before execution"));
    }

    let now = Utc::now();
    let action_type: ResponseActionType = existing.action_type.parse()?;

    // Mock execution - in production, this would integrate with actual systems
    let result = execute_action_mock(&action_type, &existing.target);

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'executed', executed_at = ?1, result = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "executed", Some(serde_json::json!({
        "result": result
    }))).await?;

    Ok(action)
}

/// Mock action execution
fn execute_action_mock(action_type: &ResponseActionType, target: &str) -> String {
    match action_type {
        ResponseActionType::BlockIp => {
            format!("MOCK: Would block IP {} at firewall. In production, integrate with firewall API (e.g., Palo Alto, Cisco, pfSense).", target)
        }
        ResponseActionType::DisableAccount => {
            format!("MOCK: Would disable account '{}' in Active Directory/IAM. In production, integrate with directory services or identity provider.", target)
        }
        ResponseActionType::IsolateHost => {
            format!("MOCK: Would isolate host '{}' from network. In production, integrate with EDR (e.g., CrowdStrike, Carbon Black) or NAC.", target)
        }
        ResponseActionType::QuarantineFile => {
            format!("MOCK: Would quarantine file '{}'. In production, integrate with endpoint protection or sandbox.", target)
        }
        ResponseActionType::ResetPassword => {
            format!("MOCK: Would force password reset for '{}'. In production, integrate with IAM system.", target)
        }
        ResponseActionType::RevokeSessions => {
            format!("MOCK: Would revoke all sessions for '{}'. In production, integrate with SSO/session management.", target)
        }
        ResponseActionType::KillProcess => {
            format!("MOCK: Would kill process '{}' on affected systems. In production, integrate with EDR or remote management.", target)
        }
        ResponseActionType::CollectForensics => {
            format!("MOCK: Would collect forensic data from '{}'. In production, integrate with forensic tools (e.g., Velociraptor, GRR).", target)
        }
        ResponseActionType::SendNotification => {
            format!("MOCK: Would send notification to '{}'. In production, integrate with notification system (Slack, email, PagerDuty).", target)
        }
        ResponseActionType::CreateTicket => {
            format!("MOCK: Would create ticket for '{}'. In production, integrate with ticketing system (JIRA, ServiceNow).", target)
        }
        ResponseActionType::CustomScript => {
            format!("MOCK: Would execute custom script for '{}'. In production, execute sandboxed script with proper authorization.", target)
        }
    }
}

/// Mark action as failed
pub async fn fail_action(
    pool: &SqlitePool,
    action_id: &str,
    error: &str,
) -> Result<ResponseAction> {
    let now = Utc::now();

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'failed', executed_at = ?1, result = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(error)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "failed", Some(serde_json::json!({
        "error": error
    }))).await?;

    Ok(action)
}

/// Cancel an action
pub async fn cancel_action(
    pool: &SqlitePool,
    action_id: &str,
    user_id: &str,
    notes: Option<&str>,
) -> Result<ResponseAction> {
    let existing = get_action(pool, action_id).await?;

    if existing.status != "pending" && existing.status != "approved" {
        return Err(anyhow::anyhow!("Cannot cancel action in {} status", existing.status));
    }

    let result = notes.map(|n| format!("Cancelled: {}", n));

    let action = sqlx::query_as::<_, ResponseAction>(
        r#"
        UPDATE response_actions
        SET status = 'cancelled', result = ?1
        WHERE id = ?2
        RETURNING *
        "#,
    )
    .bind(&result)
    .bind(action_id)
    .fetch_one(pool)
    .await?;

    log_action_event(pool, action_id, "cancelled", Some(serde_json::json!({
        "cancelled_by": user_id,
        "notes": notes
    }))).await?;

    Ok(action)
}

// ============================================================================
// Action Audit Logging
// ============================================================================

/// Log an action event
pub async fn log_action_event(
    pool: &SqlitePool,
    action_id: &str,
    event: &str,
    details: Option<serde_json::Value>,
) -> Result<ActionAuditLog> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let details_str = details.map(|d| serde_json::to_string(&d)).transpose()?;

    let log = sqlx::query_as::<_, ActionAuditLog>(
        r#"
        INSERT INTO action_audit_log
        (id, action_id, event, details, timestamp)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(action_id)
    .bind(event)
    .bind(&details_str)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(log)
}

/// Get audit log for an action
pub async fn get_action_audit_log(
    pool: &SqlitePool,
    action_id: &str,
) -> Result<Vec<ActionAuditLog>> {
    let logs = sqlx::query_as::<_, ActionAuditLog>(
        "SELECT * FROM action_audit_log WHERE action_id = ?1 ORDER BY timestamp ASC"
    )
    .bind(action_id)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

// ============================================================================
// Built-in Playbook Seeding
// ============================================================================

/// Seed default built-in playbooks
pub async fn seed_builtin_playbooks(pool: &SqlitePool) -> Result<()> {
    // Check if already seeded
    let existing = list_builtin_playbooks(pool).await?;
    if !existing.is_empty() {
        log::info!("Playbooks already seeded ({} playbooks)", existing.len());
        return Ok(());
    }

    log::info!("Seeding built-in response playbooks...");

    // Malware Containment Playbook
    create_builtin_playbook(
        pool,
        "Malware Containment",
        Some("Standard playbook for containing malware infections"),
        Some(serde_json::json!({
            "classification": ["malware"],
            "severity": ["P1", "P2"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Isolate Infected Host".to_string(),
                description: Some("Isolate the infected host from the network to prevent lateral movement".to_string()),
                action_type: "isolate_host".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 2,
                name: "Kill Malicious Process".to_string(),
                description: Some("Terminate the malicious process if identified".to_string()),
                action_type: "kill_process".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 3,
                name: "Quarantine Malware".to_string(),
                description: Some("Move malware sample to secure quarantine".to_string()),
                action_type: "quarantine_file".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 4,
                name: "Collect Forensics".to_string(),
                description: Some("Collect memory dump and relevant artifacts".to_string()),
                action_type: "collect_forensics".to_string(),
                parameters: None,
                requires_approval: false,
                timeout_seconds: Some(1800),
            },
            PlaybookStep {
                order: 5,
                name: "Notify SOC Team".to_string(),
                description: Some("Send notification to SOC team with incident details".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "channel": "soc-alerts"
                })),
                requires_approval: false,
                timeout_seconds: Some(30),
            },
        ],
    ).await?;

    // Credential Compromise Playbook
    create_builtin_playbook(
        pool,
        "Credential Compromise Response",
        Some("Standard playbook for responding to credential compromise"),
        Some(serde_json::json!({
            "classification": ["credential_compromise", "unauthorized_access"],
            "severity": ["P1", "P2", "P3"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Revoke User Sessions".to_string(),
                description: Some("Force logout from all active sessions".to_string()),
                action_type: "revoke_sessions".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 2,
                name: "Reset User Password".to_string(),
                description: Some("Force password reset for affected account".to_string()),
                action_type: "reset_password".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 3,
                name: "Block Suspicious IPs".to_string(),
                description: Some("Block IP addresses associated with unauthorized access".to_string()),
                action_type: "block_ip".to_string(),
                parameters: None,
                requires_approval: true,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 4,
                name: "Create Security Ticket".to_string(),
                description: Some("Create ticket for security team follow-up".to_string()),
                action_type: "create_ticket".to_string(),
                parameters: Some(serde_json::json!({
                    "type": "security_incident"
                })),
                requires_approval: false,
                timeout_seconds: Some(60),
            },
        ],
    ).await?;

    // Phishing Response Playbook
    create_builtin_playbook(
        pool,
        "Phishing Response",
        Some("Standard playbook for responding to phishing attempts"),
        Some(serde_json::json!({
            "classification": ["phishing", "social_engineering"],
            "severity": ["P2", "P3", "P4"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Block Phishing Domain".to_string(),
                description: Some("Block the phishing domain/URL at proxy and DNS".to_string()),
                action_type: "block_ip".to_string(),
                parameters: Some(serde_json::json!({
                    "block_type": "domain"
                })),
                requires_approval: false,
                timeout_seconds: Some(60),
            },
            PlaybookStep {
                order: 2,
                name: "Search for Other Victims".to_string(),
                description: Some("Search email logs for other recipients of the phishing email".to_string()),
                action_type: "custom_script".to_string(),
                parameters: Some(serde_json::json!({
                    "script": "email_search"
                })),
                requires_approval: false,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 3,
                name: "Notify Affected Users".to_string(),
                description: Some("Send notification to potentially affected users".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "template": "phishing_warning"
                })),
                requires_approval: true,
                timeout_seconds: Some(60),
            },
        ],
    ).await?;

    // DDoS Response Playbook
    create_builtin_playbook(
        pool,
        "DDoS Mitigation",
        Some("Standard playbook for responding to DDoS attacks"),
        Some(serde_json::json!({
            "classification": ["denial_of_service"],
            "severity": ["P1", "P2"]
        })),
        vec![
            PlaybookStep {
                order: 1,
                name: "Enable DDoS Mitigation".to_string(),
                description: Some("Activate DDoS mitigation service or scrubbing center".to_string()),
                action_type: "custom_script".to_string(),
                parameters: Some(serde_json::json!({
                    "script": "enable_ddos_mitigation"
                })),
                requires_approval: true,
                timeout_seconds: Some(120),
            },
            PlaybookStep {
                order: 2,
                name: "Block Attack IPs".to_string(),
                description: Some("Block identified attack source IPs".to_string()),
                action_type: "block_ip".to_string(),
                parameters: Some(serde_json::json!({
                    "bulk": true
                })),
                requires_approval: false,
                timeout_seconds: Some(300),
            },
            PlaybookStep {
                order: 3,
                name: "Notify NOC".to_string(),
                description: Some("Escalate to Network Operations Center".to_string()),
                action_type: "send_notification".to_string(),
                parameters: Some(serde_json::json!({
                    "channel": "noc-alerts",
                    "priority": "critical"
                })),
                requires_approval: false,
                timeout_seconds: Some(30),
            },
        ],
    ).await?;

    log::info!("Seeded 4 built-in response playbooks");
    Ok(())
}
