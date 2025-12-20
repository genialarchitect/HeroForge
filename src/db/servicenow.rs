//! Database operations for ServiceNow integration
//!
//! This module handles all database operations related to ServiceNow settings
//! and ticket tracking.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteRow;
use sqlx::{FromRow, Row, SqlitePool};

// ============================================================================
// ServiceNow Settings
// ============================================================================

/// ServiceNow settings stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowSettings {
    pub user_id: String,
    pub instance_url: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_encrypted: String,
    pub default_assignment_group: Option<String>,
    pub default_category: Option<String>,
    pub default_impact: i32,
    pub default_urgency: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, SqliteRow> for ServiceNowSettings {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            user_id: row.try_get("user_id")?,
            instance_url: row.try_get("instance_url")?,
            username: row.try_get("username")?,
            password_encrypted: row.try_get("password_encrypted")?,
            default_assignment_group: row.try_get("default_assignment_group")?,
            default_category: row.try_get("default_category")?,
            default_impact: row.try_get("default_impact")?,
            default_urgency: row.try_get("default_urgency")?,
            enabled: row.try_get::<i32, _>("enabled")? != 0,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Request to create or update ServiceNow settings
#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertServiceNowSettingsRequest {
    pub instance_url: String,
    pub username: String,
    pub password: String,
    pub default_assignment_group: Option<String>,
    pub default_category: Option<String>,
    pub default_impact: Option<i32>,
    pub default_urgency: Option<i32>,
    pub enabled: bool,
}

/// Get ServiceNow settings for a user
pub async fn get_servicenow_settings(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<ServiceNowSettings>> {
    let settings = sqlx::query_as::<_, ServiceNowSettings>(
        "SELECT * FROM servicenow_settings WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(settings)
}

/// Create or update ServiceNow settings for a user
pub async fn upsert_servicenow_settings(
    pool: &SqlitePool,
    user_id: &str,
    request: &UpsertServiceNowSettingsRequest,
) -> Result<ServiceNowSettings> {
    let now = Utc::now();
    let impact = request.default_impact.unwrap_or(3);
    let urgency = request.default_urgency.unwrap_or(3);

    // Check if settings exist
    let exists: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM servicenow_settings WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await?;

    if exists.0 > 0 {
        // Update existing settings
        sqlx::query(
            r#"
            UPDATE servicenow_settings
            SET instance_url = ?, username = ?, password_encrypted = ?,
                default_assignment_group = ?, default_category = ?,
                default_impact = ?, default_urgency = ?, enabled = ?, updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(&request.instance_url)
        .bind(&request.username)
        .bind(&request.password)
        .bind(&request.default_assignment_group)
        .bind(&request.default_category)
        .bind(impact)
        .bind(urgency)
        .bind(request.enabled as i32)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    } else {
        // Insert new settings
        sqlx::query(
            r#"
            INSERT INTO servicenow_settings (
                user_id, instance_url, username, password_encrypted,
                default_assignment_group, default_category,
                default_impact, default_urgency, enabled, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(user_id)
        .bind(&request.instance_url)
        .bind(&request.username)
        .bind(&request.password)
        .bind(&request.default_assignment_group)
        .bind(&request.default_category)
        .bind(impact)
        .bind(urgency)
        .bind(request.enabled as i32)
        .bind(now)
        .bind(now)
        .execute(pool)
        .await?;
    }

    // Return the updated settings
    get_servicenow_settings(pool, user_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Failed to retrieve settings after save"))
}

/// Delete ServiceNow settings for a user
pub async fn delete_servicenow_settings(pool: &SqlitePool, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM servicenow_settings WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// ServiceNow Tickets
// ============================================================================

/// ServiceNow ticket tracking record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowTicket {
    pub id: String,
    pub vulnerability_id: String,
    pub ticket_number: String,
    pub ticket_type: String,
    pub ticket_sys_id: String,
    pub ticket_url: String,
    pub status: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl<'r> FromRow<'r, SqliteRow> for ServiceNowTicket {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            vulnerability_id: row.try_get("vulnerability_id")?,
            ticket_number: row.try_get("ticket_number")?,
            ticket_type: row.try_get("ticket_type")?,
            ticket_sys_id: row.try_get("ticket_sys_id")?,
            ticket_url: row.try_get("ticket_url")?,
            status: row.try_get("status")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Request to create a ServiceNow ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServiceNowTicketRequest {
    pub ticket_type: String,  // "incident" or "change"
    pub category: Option<String>,
    pub assignment_group: Option<String>,
}

/// Response after creating a ServiceNow ticket
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServiceNowTicketResponse {
    pub id: String,
    pub ticket_number: String,
    pub ticket_type: String,
    pub ticket_url: String,
}

/// Create a ServiceNow ticket record
pub async fn create_servicenow_ticket(
    pool: &SqlitePool,
    vulnerability_id: &str,
    ticket_number: &str,
    ticket_type: &str,
    ticket_sys_id: &str,
    instance_url: &str,
    created_by: &str,
) -> Result<ServiceNowTicket> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    // Build ticket URL
    let ticket_url = format!("{}/nav_to.do?uri=/{}.do?sys_id={}",
        instance_url.trim_end_matches('/'),
        if ticket_type == "incident" { "incident" } else { "change_request" },
        ticket_sys_id
    );

    sqlx::query(
        r#"
        INSERT INTO servicenow_tickets (
            id, vulnerability_id, ticket_number, ticket_type,
            ticket_sys_id, ticket_url, created_by, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(vulnerability_id)
    .bind(ticket_number)
    .bind(ticket_type)
    .bind(ticket_sys_id)
    .bind(&ticket_url)
    .bind(created_by)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(ServiceNowTicket {
        id,
        vulnerability_id: vulnerability_id.to_string(),
        ticket_number: ticket_number.to_string(),
        ticket_type: ticket_type.to_string(),
        ticket_sys_id: ticket_sys_id.to_string(),
        ticket_url,
        status: None,
        created_by: created_by.to_string(),
        created_at: now,
        updated_at: now,
    })
}

/// Get ServiceNow tickets for a vulnerability
pub async fn get_tickets_for_vulnerability(
    pool: &SqlitePool,
    vulnerability_id: &str,
) -> Result<Vec<ServiceNowTicket>> {
    let tickets = sqlx::query_as::<_, ServiceNowTicket>(
        "SELECT * FROM servicenow_tickets WHERE vulnerability_id = ? ORDER BY created_at DESC",
    )
    .bind(vulnerability_id)
    .fetch_all(pool)
    .await?;

    Ok(tickets)
}

/// Get a ServiceNow ticket by ID
pub async fn get_servicenow_ticket_by_id(
    pool: &SqlitePool,
    ticket_id: &str,
) -> Result<Option<ServiceNowTicket>> {
    let ticket = sqlx::query_as::<_, ServiceNowTicket>(
        "SELECT * FROM servicenow_tickets WHERE id = ?",
    )
    .bind(ticket_id)
    .fetch_optional(pool)
    .await?;

    Ok(ticket)
}

/// Get a ServiceNow ticket by ticket number
pub async fn get_servicenow_ticket_by_number(
    pool: &SqlitePool,
    ticket_number: &str,
) -> Result<Option<ServiceNowTicket>> {
    let ticket = sqlx::query_as::<_, ServiceNowTicket>(
        "SELECT * FROM servicenow_tickets WHERE ticket_number = ?",
    )
    .bind(ticket_number)
    .fetch_optional(pool)
    .await?;

    Ok(ticket)
}

/// Update ticket status
pub async fn update_servicenow_ticket_status(
    pool: &SqlitePool,
    ticket_id: &str,
    status: &str,
) -> Result<bool> {
    let now = Utc::now();

    let result = sqlx::query(
        "UPDATE servicenow_tickets SET status = ?, updated_at = ? WHERE id = ?",
    )
    .bind(status)
    .bind(now)
    .bind(ticket_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete a ServiceNow ticket record
pub async fn delete_servicenow_ticket(pool: &SqlitePool, ticket_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM servicenow_tickets WHERE id = ?")
        .bind(ticket_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get all tickets created by a user
pub async fn get_user_servicenow_tickets(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ServiceNowTicket>> {
    let tickets = sqlx::query_as::<_, ServiceNowTicket>(
        "SELECT * FROM servicenow_tickets WHERE created_by = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(tickets)
}
