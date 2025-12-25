//! Enhanced remediation workflow database operations
//!
//! This module provides functions for:
//! - Verification request management
//! - Ticket sync (JIRA/ServiceNow) bidirectional synchronization
//! - SLA configuration and tracking
//! - Remediation escalations
//! - Assignment history

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Verification request status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Pending,
    InProgress,
    Passed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Passed => write!(f, "passed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Verification request type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationType {
    Retest,
    ManualReview,
    AutomatedScan,
    PeerReview,
}

impl std::fmt::Display for VerificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retest => write!(f, "retest"),
            Self::ManualReview => write!(f, "manual_review"),
            Self::AutomatedScan => write!(f, "automated_scan"),
            Self::PeerReview => write!(f, "peer_review"),
        }
    }
}

/// Ticket sync integration type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationType {
    Jira,
    ServiceNow,
}

impl std::fmt::Display for IntegrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jira => write!(f, "jira"),
            Self::ServiceNow => write!(f, "servicenow"),
        }
    }
}

/// Sync status for ticket synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Synced,
    Pending,
    Error,
    Conflict,
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Synced => write!(f, "synced"),
            Self::Pending => write!(f, "pending"),
            Self::Error => write!(f, "error"),
            Self::Conflict => write!(f, "conflict"),
        }
    }
}

/// Verification request record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VerificationRequest {
    pub id: String,
    pub vulnerability_id: String,
    pub requested_by: String,
    pub assigned_to: Option<String>,
    pub scan_id: Option<String>,
    pub verification_type: String,
    pub status: String,
    pub priority: i32,
    pub notes: Option<String>,
    pub verification_evidence: Option<String>,
    pub result: Option<String>,
    pub result_details: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

/// Verification request with user details
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VerificationRequestWithUsers {
    pub id: String,
    pub vulnerability_id: String,
    pub requested_by: String,
    pub requested_by_username: String,
    pub assigned_to: Option<String>,
    pub assigned_to_username: Option<String>,
    pub scan_id: Option<String>,
    pub verification_type: String,
    pub status: String,
    pub priority: i32,
    pub notes: Option<String>,
    pub verification_evidence: Option<String>,
    pub result: Option<String>,
    pub result_details: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

/// Ticket sync record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TicketSync {
    pub id: String,
    pub vulnerability_id: String,
    pub integration_type: String,
    pub external_id: String,
    pub external_url: Option<String>,
    pub external_status: Option<String>,
    pub external_priority: Option<String>,
    pub external_assignee: Option<String>,
    pub sync_status: String,
    pub sync_direction: String,
    pub last_synced_at: Option<String>,
    pub last_sync_error: Option<String>,
    pub field_mappings: Option<String>,
    pub auto_sync_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Ticket sync history record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TicketSyncHistory {
    pub id: String,
    pub ticket_sync_id: String,
    pub sync_direction: String,
    pub sync_type: String,
    pub fields_updated: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// SLA configuration record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemediationSlaConfig {
    pub id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub target_days: i32,
    pub warning_threshold_days: Option<i32>,
    pub escalation_emails: Option<String>,
    pub is_default: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Remediation assignment record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemediationAssignment {
    pub id: String,
    pub vulnerability_id: String,
    pub assigned_by: String,
    pub assigned_to: String,
    pub previous_assignee: Option<String>,
    pub reason: Option<String>,
    pub due_date: Option<String>,
    pub created_at: String,
}

/// Remediation assignment with user details
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemediationAssignmentWithUsers {
    pub id: String,
    pub vulnerability_id: String,
    pub assigned_by: String,
    pub assigned_by_username: String,
    pub assigned_to: String,
    pub assigned_to_username: String,
    pub previous_assignee: Option<String>,
    pub previous_assignee_username: Option<String>,
    pub reason: Option<String>,
    pub due_date: Option<String>,
    pub created_at: String,
}

/// Remediation escalation record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RemediationEscalation {
    pub id: String,
    pub vulnerability_id: String,
    pub escalation_level: i32,
    pub escalation_reason: String,
    pub escalated_to: Option<String>,
    pub escalated_by: Option<String>,
    pub notes: Option<String>,
    pub acknowledged_at: Option<String>,
    pub acknowledged_by: Option<String>,
    pub created_at: String,
}

/// Create verification request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateVerificationRequest {
    pub vulnerability_id: String,
    pub verification_type: Option<String>,
    pub assigned_to: Option<String>,
    pub priority: Option<i32>,
    pub notes: Option<String>,
}

/// Update verification request
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateVerificationRequest {
    pub status: Option<String>,
    pub assigned_to: Option<String>,
    pub result: Option<String>,
    pub result_details: Option<String>,
    pub verification_evidence: Option<String>,
    pub notes: Option<String>,
}

/// Create ticket sync request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTicketSyncRequest {
    pub vulnerability_id: String,
    pub integration_type: String,
    pub external_id: String,
    pub external_url: Option<String>,
    pub sync_direction: Option<String>,
    pub auto_sync_enabled: Option<bool>,
}

/// Overdue vulnerability summary
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OverdueVulnerability {
    pub id: String,
    pub vulnerability_id: String,
    pub host_ip: String,
    pub port: Option<i32>,
    pub severity: String,
    pub status: String,
    pub due_date: String,
    pub days_overdue: i64,
    pub assignee_id: Option<String>,
    pub assignee_username: Option<String>,
}

/// SLA breach summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBreachSummary {
    pub total_overdue: i64,
    pub critical_overdue: i64,
    pub high_overdue: i64,
    pub medium_overdue: i64,
    pub low_overdue: i64,
    pub avg_days_overdue: f64,
}

// ============================================================================
// Verification Requests
// ============================================================================

/// Create a new verification request
pub async fn create_verification_request(
    pool: &SqlitePool,
    user_id: &str,
    request: CreateVerificationRequest,
) -> Result<VerificationRequest> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let verification_type = request.verification_type.unwrap_or_else(|| "retest".to_string());
    let priority = request.priority.unwrap_or(0);

    let result = sqlx::query_as::<_, VerificationRequest>(
        r#"
        INSERT INTO verification_requests
        (id, vulnerability_id, requested_by, assigned_to, verification_type, status, priority, notes, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.vulnerability_id)
    .bind(user_id)
    .bind(&request.assigned_to)
    .bind(&verification_type)
    .bind(priority)
    .bind(&request.notes)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get verification request by ID
pub async fn get_verification_request_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<VerificationRequest>> {
    let result = sqlx::query_as::<_, VerificationRequest>(
        "SELECT * FROM verification_requests WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Get verification requests for a vulnerability
pub async fn get_verification_requests_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<VerificationRequestWithUsers>> {
    let results = sqlx::query_as::<_, VerificationRequestWithUsers>(
        r#"
        SELECT
            vr.id, vr.vulnerability_id, vr.requested_by,
            u1.username as requested_by_username,
            vr.assigned_to, u2.username as assigned_to_username,
            vr.scan_id, vr.verification_type, vr.status, vr.priority,
            vr.notes, vr.verification_evidence, vr.result, vr.result_details,
            vr.created_at, vr.updated_at, vr.completed_at
        FROM verification_requests vr
        JOIN users u1 ON vr.requested_by = u1.id
        LEFT JOIN users u2 ON vr.assigned_to = u2.id
        WHERE vr.vulnerability_id = ?1
        ORDER BY vr.created_at DESC
        "#,
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Get pending verification requests assigned to user
pub async fn get_pending_verification_requests(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<VerificationRequestWithUsers>> {
    let results = sqlx::query_as::<_, VerificationRequestWithUsers>(
        r#"
        SELECT
            vr.id, vr.vulnerability_id, vr.requested_by,
            u1.username as requested_by_username,
            vr.assigned_to, u2.username as assigned_to_username,
            vr.scan_id, vr.verification_type, vr.status, vr.priority,
            vr.notes, vr.verification_evidence, vr.result, vr.result_details,
            vr.created_at, vr.updated_at, vr.completed_at
        FROM verification_requests vr
        JOIN users u1 ON vr.requested_by = u1.id
        LEFT JOIN users u2 ON vr.assigned_to = u2.id
        WHERE vr.assigned_to = ?1 AND vr.status IN ('pending', 'in_progress')
        ORDER BY vr.priority DESC, vr.created_at ASC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Update verification request
pub async fn update_verification_request(
    pool: &SqlitePool,
    id: &str,
    request: UpdateVerificationRequest,
) -> Result<VerificationRequest> {
    let now = Utc::now().to_rfc3339();
    let completed_at = if request.status.as_deref() == Some("passed")
        || request.status.as_deref() == Some("failed")
        || request.status.as_deref() == Some("cancelled")
    {
        Some(now.clone())
    } else {
        None
    };

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?1"];

    if request.status.is_some() {
        updates.push("status = ?");
    }
    if request.assigned_to.is_some() {
        updates.push("assigned_to = ?");
    }
    if request.result.is_some() {
        updates.push("result = ?");
    }
    if request.result_details.is_some() {
        updates.push("result_details = ?");
    }
    if request.verification_evidence.is_some() {
        updates.push("verification_evidence = ?");
    }
    if request.notes.is_some() {
        updates.push("notes = ?");
    }
    if completed_at.is_some() {
        updates.push("completed_at = ?");
    }

    let query = format!(
        "UPDATE verification_requests SET {} WHERE id = ? RETURNING *",
        updates.join(", ")
    );

    let mut q = sqlx::query_as::<_, VerificationRequest>(&query);
    q = q.bind(&now);

    if let Some(ref status) = request.status {
        q = q.bind(status);
    }
    if let Some(ref assigned_to) = request.assigned_to {
        q = q.bind(assigned_to);
    }
    if let Some(ref result) = request.result {
        q = q.bind(result);
    }
    if let Some(ref result_details) = request.result_details {
        q = q.bind(result_details);
    }
    if let Some(ref verification_evidence) = request.verification_evidence {
        q = q.bind(verification_evidence);
    }
    if let Some(ref notes) = request.notes {
        q = q.bind(notes);
    }
    if let Some(ref ca) = completed_at {
        q = q.bind(ca);
    }
    q = q.bind(id);

    let result = q.fetch_one(pool).await?;
    Ok(result)
}

/// Complete a verification request (mark as passed or failed)
pub async fn complete_verification_request(
    pool: &SqlitePool,
    id: &str,
    passed: bool,
    result_details: Option<&str>,
    evidence: Option<&str>,
) -> Result<VerificationRequest> {
    let now = Utc::now().to_rfc3339();
    let status = if passed { "passed" } else { "failed" };
    let result = if passed { "verified" } else { "still_vulnerable" };

    let updated = sqlx::query_as::<_, VerificationRequest>(
        r#"
        UPDATE verification_requests
        SET status = ?1, result = ?2, result_details = ?3, verification_evidence = ?4,
            completed_at = ?5, updated_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(status)
    .bind(result)
    .bind(result_details)
    .bind(evidence)
    .bind(&now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

// ============================================================================
// Ticket Sync
// ============================================================================

/// Create a new ticket sync record
pub async fn create_ticket_sync(
    pool: &SqlitePool,
    request: CreateTicketSyncRequest,
) -> Result<TicketSync> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let sync_direction = request.sync_direction.unwrap_or_else(|| "bidirectional".to_string());
    let auto_sync = request.auto_sync_enabled.unwrap_or(true);

    let result = sqlx::query_as::<_, TicketSync>(
        r#"
        INSERT INTO ticket_sync
        (id, vulnerability_id, integration_type, external_id, external_url, sync_status,
         sync_direction, auto_sync_enabled, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, 'synced', ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&request.vulnerability_id)
    .bind(&request.integration_type)
    .bind(&request.external_id)
    .bind(&request.external_url)
    .bind(&sync_direction)
    .bind(auto_sync)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get ticket sync by vulnerability and integration type
pub async fn get_ticket_sync(
    pool: &SqlitePool,
    vulnerability_id: &str,
    integration_type: &str,
) -> Result<Option<TicketSync>> {
    let result = sqlx::query_as::<_, TicketSync>(
        "SELECT * FROM ticket_sync WHERE vulnerability_id = ?1 AND integration_type = ?2",
    )
    .bind(vulnerability_id)
    .bind(integration_type)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Get all ticket syncs for a vulnerability
pub async fn get_ticket_syncs_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<TicketSync>> {
    let results = sqlx::query_as::<_, TicketSync>(
        "SELECT * FROM ticket_sync WHERE vulnerability_id = ?1 ORDER BY created_at DESC",
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Update ticket sync with external status
pub async fn update_ticket_sync_status(
    pool: &SqlitePool,
    id: &str,
    external_status: Option<&str>,
    external_priority: Option<&str>,
    external_assignee: Option<&str>,
) -> Result<TicketSync> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, TicketSync>(
        r#"
        UPDATE ticket_sync
        SET external_status = COALESCE(?1, external_status),
            external_priority = COALESCE(?2, external_priority),
            external_assignee = COALESCE(?3, external_assignee),
            sync_status = 'synced',
            last_synced_at = ?4,
            last_sync_error = NULL,
            updated_at = ?4
        WHERE id = ?5
        RETURNING *
        "#,
    )
    .bind(external_status)
    .bind(external_priority)
    .bind(external_assignee)
    .bind(&now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Mark ticket sync as error
pub async fn mark_ticket_sync_error(
    pool: &SqlitePool,
    id: &str,
    error_message: &str,
) -> Result<TicketSync> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, TicketSync>(
        r#"
        UPDATE ticket_sync
        SET sync_status = 'error', last_sync_error = ?1, updated_at = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(error_message)
    .bind(&now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Log ticket sync operation
pub async fn log_ticket_sync_operation(
    pool: &SqlitePool,
    ticket_sync_id: &str,
    sync_direction: &str,
    sync_type: &str,
    fields_updated: Option<&str>,
    status: &str,
    error_message: Option<&str>,
) -> Result<TicketSyncHistory> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, TicketSyncHistory>(
        r#"
        INSERT INTO ticket_sync_history
        (id, ticket_sync_id, sync_direction, sync_type, fields_updated, status, error_message, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(ticket_sync_id)
    .bind(sync_direction)
    .bind(sync_type)
    .bind(fields_updated)
    .bind(status)
    .bind(error_message)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get ticket sync history
pub async fn get_ticket_sync_history(
    pool: &SqlitePool,
    ticket_sync_id: &str,
    limit: Option<i32>,
) -> Result<Vec<TicketSyncHistory>> {
    let limit = limit.unwrap_or(50);

    let results = sqlx::query_as::<_, TicketSyncHistory>(
        "SELECT * FROM ticket_sync_history WHERE ticket_sync_id = ?1 ORDER BY created_at DESC LIMIT ?2",
    )
    .bind(ticket_sync_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

// ============================================================================
// SLA Configuration
// ============================================================================

/// Get SLA config for severity (organization-specific or default)
pub async fn get_sla_config_for_severity(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    severity: &str,
) -> Result<Option<RemediationSlaConfig>> {
    // First try org-specific config
    if let Some(org_id) = organization_id {
        let result = sqlx::query_as::<_, RemediationSlaConfig>(
            r#"
            SELECT * FROM remediation_sla_configs
            WHERE organization_id = ?1 AND severity = ?2 AND is_active = 1
            "#,
        )
        .bind(org_id)
        .bind(severity)
        .fetch_optional(pool)
        .await?;

        if result.is_some() {
            return Ok(result);
        }
    }

    // Fall back to default config
    let result = sqlx::query_as::<_, RemediationSlaConfig>(
        r#"
        SELECT * FROM remediation_sla_configs
        WHERE organization_id IS NULL AND severity = ?1 AND is_default = 1 AND is_active = 1
        "#,
    )
    .bind(severity)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Get all SLA configs for organization
pub async fn get_sla_configs(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<Vec<RemediationSlaConfig>> {
    let results = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, RemediationSlaConfig>(
            "SELECT * FROM remediation_sla_configs WHERE (organization_id = ?1 OR organization_id IS NULL) AND is_active = 1 ORDER BY severity",
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, RemediationSlaConfig>(
            "SELECT * FROM remediation_sla_configs WHERE organization_id IS NULL AND is_active = 1 ORDER BY severity",
        )
        .fetch_all(pool)
        .await?
    };

    Ok(results)
}

/// Create custom SLA config for organization
pub async fn create_sla_config(
    pool: &SqlitePool,
    organization_id: &str,
    name: &str,
    severity: &str,
    target_days: i32,
    warning_threshold_days: Option<i32>,
    escalation_emails: Option<&str>,
) -> Result<RemediationSlaConfig> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, RemediationSlaConfig>(
        r#"
        INSERT INTO remediation_sla_configs
        (id, organization_id, name, severity, target_days, warning_threshold_days, escalation_emails, is_default, is_active, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 1, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(organization_id)
    .bind(name)
    .bind(severity)
    .bind(target_days)
    .bind(warning_threshold_days)
    .bind(escalation_emails)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Calculate due date for a vulnerability based on SLA
pub async fn calculate_due_date(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    severity: &str,
    created_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>> {
    if let Some(config) = get_sla_config_for_severity(pool, organization_id, severity).await? {
        let due_date = created_at + Duration::days(config.target_days as i64);
        Ok(Some(due_date))
    } else {
        Ok(None)
    }
}

// ============================================================================
// Overdue Vulnerabilities
// ============================================================================

/// Get overdue vulnerabilities
pub async fn get_overdue_vulnerabilities(
    pool: &SqlitePool,
    organization_id: Option<&str>,
    limit: Option<i32>,
) -> Result<Vec<OverdueVulnerability>> {
    let limit = limit.unwrap_or(100);
    let now = Utc::now().to_rfc3339();

    let results = if let Some(org_id) = organization_id {
        sqlx::query_as::<_, OverdueVulnerability>(
            r#"
            SELECT
                vt.id, vt.vulnerability_id, vt.host_ip, vt.port, vt.severity, vt.status,
                vt.due_date,
                CAST((julianday(?1) - julianday(vt.due_date)) AS INTEGER) as days_overdue,
                vt.assignee_id,
                u.username as assignee_username
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.organization_id = ?2
              AND vt.due_date IS NOT NULL
              AND vt.due_date < ?1
              AND vt.status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            ORDER BY days_overdue DESC
            LIMIT ?3
            "#,
        )
        .bind(&now)
        .bind(org_id)
        .bind(limit)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, OverdueVulnerability>(
            r#"
            SELECT
                vt.id, vt.vulnerability_id, vt.host_ip, vt.port, vt.severity, vt.status,
                vt.due_date,
                CAST((julianday(?1) - julianday(vt.due_date)) AS INTEGER) as days_overdue,
                vt.assignee_id,
                u.username as assignee_username
            FROM vulnerability_tracking vt
            LEFT JOIN users u ON vt.assignee_id = u.id
            WHERE vt.due_date IS NOT NULL
              AND vt.due_date < ?1
              AND vt.status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            ORDER BY days_overdue DESC
            LIMIT ?2
            "#,
        )
        .bind(&now)
        .bind(limit)
        .fetch_all(pool)
        .await?
    };

    Ok(results)
}

/// Get SLA breach summary
pub async fn get_sla_breach_summary(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<SlaBreachSummary> {
    let now = Utc::now().to_rfc3339();

    let (query, params): (&str, Vec<String>) = if let Some(org_id) = organization_id {
        (
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                AVG(julianday(?1) - julianday(due_date)) as avg_days
            FROM vulnerability_tracking
            WHERE organization_id = ?2
              AND due_date IS NOT NULL
              AND due_date < ?1
              AND status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            "#,
            vec![now.clone(), org_id.to_string()],
        )
    } else {
        (
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
                AVG(julianday(?1) - julianday(due_date)) as avg_days
            FROM vulnerability_tracking
            WHERE due_date IS NOT NULL
              AND due_date < ?1
              AND status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            "#,
            vec![now.clone()],
        )
    };

    let row: (i64, i64, i64, i64, i64, Option<f64>) = {
        let mut q = sqlx::query_as(query);
        for param in &params {
            q = q.bind(param);
        }
        q.fetch_one(pool).await?
    };

    Ok(SlaBreachSummary {
        total_overdue: row.0,
        critical_overdue: row.1,
        high_overdue: row.2,
        medium_overdue: row.3,
        low_overdue: row.4,
        avg_days_overdue: row.5.unwrap_or(0.0),
    })
}

// ============================================================================
// Remediation Assignments
// ============================================================================

/// Record a remediation assignment
pub async fn create_remediation_assignment(
    pool: &SqlitePool,
    vulnerability_id: &str,
    assigned_by: &str,
    assigned_to: &str,
    previous_assignee: Option<&str>,
    reason: Option<&str>,
    due_date: Option<&str>,
) -> Result<RemediationAssignment> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, RemediationAssignment>(
        r#"
        INSERT INTO remediation_assignments
        (id, vulnerability_id, assigned_by, assigned_to, previous_assignee, reason, due_date, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(vulnerability_id)
    .bind(assigned_by)
    .bind(assigned_to)
    .bind(previous_assignee)
    .bind(reason)
    .bind(due_date)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get assignment history for a vulnerability
pub async fn get_assignment_history(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<RemediationAssignmentWithUsers>> {
    let results = sqlx::query_as::<_, RemediationAssignmentWithUsers>(
        r#"
        SELECT
            ra.id, ra.vulnerability_id,
            ra.assigned_by, u1.username as assigned_by_username,
            ra.assigned_to, u2.username as assigned_to_username,
            ra.previous_assignee, u3.username as previous_assignee_username,
            ra.reason, ra.due_date, ra.created_at
        FROM remediation_assignments ra
        JOIN users u1 ON ra.assigned_by = u1.id
        JOIN users u2 ON ra.assigned_to = u2.id
        LEFT JOIN users u3 ON ra.previous_assignee = u3.id
        WHERE ra.vulnerability_id = ?1
        ORDER BY ra.created_at DESC
        "#,
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

// ============================================================================
// Escalations
// ============================================================================

/// Create an escalation
pub async fn create_escalation(
    pool: &SqlitePool,
    vulnerability_id: &str,
    escalation_level: i32,
    escalation_reason: &str,
    escalated_to: Option<&str>,
    escalated_by: Option<&str>,
    notes: Option<&str>,
) -> Result<RemediationEscalation> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, RemediationEscalation>(
        r#"
        INSERT INTO remediation_escalations
        (id, vulnerability_id, escalation_level, escalation_reason, escalated_to, escalated_by, notes, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(vulnerability_id)
    .bind(escalation_level)
    .bind(escalation_reason)
    .bind(escalated_to)
    .bind(escalated_by)
    .bind(notes)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Acknowledge an escalation
pub async fn acknowledge_escalation(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<RemediationEscalation> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query_as::<_, RemediationEscalation>(
        r#"
        UPDATE remediation_escalations
        SET acknowledged_at = ?1, acknowledged_by = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(&now)
    .bind(user_id)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(result)
}

/// Get escalations for a vulnerability
pub async fn get_escalations_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<RemediationEscalation>> {
    let results = sqlx::query_as::<_, RemediationEscalation>(
        "SELECT * FROM remediation_escalations WHERE vulnerability_id = ?1 ORDER BY escalation_level DESC, created_at DESC",
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

/// Get unacknowledged escalations for user
pub async fn get_unacknowledged_escalations(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i32>,
) -> Result<Vec<RemediationEscalation>> {
    let limit = limit.unwrap_or(50);

    let results = sqlx::query_as::<_, RemediationEscalation>(
        r#"
        SELECT * FROM remediation_escalations
        WHERE escalated_to = ?1 AND acknowledged_at IS NULL
        ORDER BY escalation_level DESC, created_at ASC
        LIMIT ?2
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(results)
}

// ============================================================================
// Remediation Dashboard Stats
// ============================================================================

/// Remediation dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDashboardStats {
    pub total_open: i64,
    pub total_in_progress: i64,
    pub total_resolved: i64,
    pub total_verified: i64,
    pub pending_verification: i64,
    pub overdue_count: i64,
    pub avg_resolution_days: f64,
    pub resolution_rate_30d: f64,
    pub by_severity: Vec<SeverityStats>,
    pub by_status: Vec<StatusStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SeverityStats {
    pub severity: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StatusStats {
    pub status: String,
    pub count: i64,
}

/// Get remediation dashboard statistics
pub async fn get_remediation_dashboard_stats(
    pool: &SqlitePool,
    organization_id: Option<&str>,
) -> Result<RemediationDashboardStats> {
    let now = Utc::now().to_rfc3339();
    let thirty_days_ago = (Utc::now() - Duration::days(30)).to_rfc3339();

    // Base counts
    let counts: (i64, i64, i64, i64) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END)
            FROM vulnerability_tracking WHERE organization_id = ?1
            "#,
        )
        .bind(org_id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END)
            FROM vulnerability_tracking
            "#,
        )
        .fetch_one(pool)
        .await?
    };

    // Pending verification count
    let pending_verification: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM verification_requests WHERE status IN ('pending', 'in_progress')",
    )
    .fetch_one(pool)
    .await?;

    // Overdue count
    let overdue: (i64,) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM vulnerability_tracking
            WHERE organization_id = ?1 AND due_date IS NOT NULL AND due_date < ?2
              AND status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            "#,
        )
        .bind(org_id)
        .bind(&now)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM vulnerability_tracking
            WHERE due_date IS NOT NULL AND due_date < ?1
              AND status NOT IN ('resolved', 'verified', 'accepted_risk', 'false_positive')
            "#,
        )
        .bind(&now)
        .fetch_one(pool)
        .await?
    };

    // Avg resolution time (for resolved in last 30 days)
    let avg_resolution: (Option<f64>,) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT AVG(julianday(resolved_at) - julianday(created_at))
            FROM vulnerability_tracking
            WHERE organization_id = ?1 AND status IN ('resolved', 'verified') AND resolved_at > ?2
            "#,
        )
        .bind(org_id)
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT AVG(julianday(resolved_at) - julianday(created_at))
            FROM vulnerability_tracking
            WHERE status IN ('resolved', 'verified') AND resolved_at > ?1
            "#,
        )
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    };

    // Resolution rate (last 30 days)
    let resolution_rate: (i64, i64) = if let Some(org_id) = organization_id {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status IN ('resolved', 'verified') THEN 1 ELSE 0 END),
                COUNT(*)
            FROM vulnerability_tracking
            WHERE organization_id = ?1 AND created_at > ?2
            "#,
        )
        .bind(org_id)
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT
                SUM(CASE WHEN status IN ('resolved', 'verified') THEN 1 ELSE 0 END),
                COUNT(*)
            FROM vulnerability_tracking
            WHERE created_at > ?1
            "#,
        )
        .bind(&thirty_days_ago)
        .fetch_one(pool)
        .await?
    };

    // By severity
    let by_severity: Vec<SeverityStats> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT severity, COUNT(*) as count FROM vulnerability_tracking WHERE organization_id = ?1 AND status NOT IN ('resolved', 'verified', 'false_positive') GROUP BY severity",
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT severity, COUNT(*) as count FROM vulnerability_tracking WHERE status NOT IN ('resolved', 'verified', 'false_positive') GROUP BY severity",
        )
        .fetch_all(pool)
        .await?
    };

    // By status
    let by_status: Vec<StatusStats> = if let Some(org_id) = organization_id {
        sqlx::query_as(
            "SELECT status, COUNT(*) as count FROM vulnerability_tracking WHERE organization_id = ?1 GROUP BY status",
        )
        .bind(org_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT status, COUNT(*) as count FROM vulnerability_tracking GROUP BY status",
        )
        .fetch_all(pool)
        .await?
    };

    let rate = if resolution_rate.1 > 0 {
        (resolution_rate.0 as f64 / resolution_rate.1 as f64) * 100.0
    } else {
        0.0
    };

    Ok(RemediationDashboardStats {
        total_open: counts.0,
        total_in_progress: counts.1,
        total_resolved: counts.2,
        total_verified: counts.3,
        pending_verification: pending_verification.0,
        overdue_count: overdue.0,
        avg_resolution_days: avg_resolution.0.unwrap_or(0.0),
        resolution_rate_30d: rate,
        by_severity,
        by_status,
    })
}
