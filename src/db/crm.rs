//! CRM Database Operations
//!
//! This module provides database operations for the CRM system including:
//! - Customers
//! - Contacts
//! - Engagements
//! - Milestones
//! - Contracts
//! - SLA Definitions
//! - Time Entries
//! - Communications
//! - Portal Users

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types and Models
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Customer {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub industry: Option<String>,
    pub company_size: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCustomerRequest {
    pub name: String,
    pub industry: Option<String>,
    pub company_size: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCustomerRequest {
    pub name: Option<String>,
    pub industry: Option<String>,
    pub company_size: Option<String>,
    pub website: Option<String>,
    pub address: Option<String>,
    pub notes: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Contact {
    pub id: String,
    pub customer_id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub is_primary: bool,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContactRequest {
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub is_primary: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContactRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
    pub is_primary: Option<bool>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Engagement {
    pub id: String,
    pub customer_id: String,
    pub name: String,
    pub engagement_type: String,
    pub status: String,
    pub scope: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub budget: Option<f64>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEngagementRequest {
    pub name: String,
    pub engagement_type: String,
    pub status: Option<String>,
    pub scope: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub budget: Option<f64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEngagementRequest {
    pub name: Option<String>,
    pub engagement_type: Option<String>,
    pub status: Option<String>,
    pub scope: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub budget: Option<f64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EngagementMilestone {
    pub id: String,
    pub engagement_id: String,
    pub name: String,
    pub description: Option<String>,
    pub due_date: Option<String>,
    pub completed_at: Option<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMilestoneRequest {
    pub name: String,
    pub description: Option<String>,
    pub due_date: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMilestoneRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub due_date: Option<String>,
    pub status: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Contract {
    pub id: String,
    pub customer_id: String,
    pub engagement_id: Option<String>,
    pub contract_type: String,
    pub name: String,
    pub value: Option<f64>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub status: String,
    pub file_path: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContractRequest {
    pub engagement_id: Option<String>,
    pub contract_type: String,
    pub name: String,
    pub value: Option<f64>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub status: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateContractRequest {
    pub engagement_id: Option<String>,
    pub contract_type: Option<String>,
    pub name: Option<String>,
    pub value: Option<f64>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub status: Option<String>,
    pub file_path: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SlaDefinition {
    pub id: String,
    pub customer_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub response_time_critical: Option<i32>,
    pub response_time_high: Option<i32>,
    pub response_time_medium: Option<i32>,
    pub response_time_low: Option<i32>,
    pub resolution_time_critical: Option<i32>,
    pub resolution_time_high: Option<i32>,
    pub resolution_time_medium: Option<i32>,
    pub resolution_time_low: Option<i32>,
    pub is_template: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSlaRequest {
    pub name: String,
    pub description: Option<String>,
    pub response_time_critical: Option<i32>,
    pub response_time_high: Option<i32>,
    pub response_time_medium: Option<i32>,
    pub response_time_low: Option<i32>,
    pub resolution_time_critical: Option<i32>,
    pub resolution_time_high: Option<i32>,
    pub resolution_time_medium: Option<i32>,
    pub resolution_time_low: Option<i32>,
    pub is_template: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TimeEntry {
    pub id: String,
    pub engagement_id: String,
    pub user_id: String,
    pub description: String,
    pub hours: f64,
    pub billable: bool,
    pub date: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTimeEntryRequest {
    pub description: String,
    pub hours: f64,
    pub billable: Option<bool>,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Communication {
    pub id: String,
    pub customer_id: String,
    pub engagement_id: Option<String>,
    pub contact_id: Option<String>,
    pub user_id: String,
    pub comm_type: String,
    pub subject: Option<String>,
    pub content: Option<String>,
    pub comm_date: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCommunicationRequest {
    pub engagement_id: Option<String>,
    pub contact_id: Option<String>,
    pub comm_type: String,
    pub subject: Option<String>,
    pub content: Option<String>,
    pub comm_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PortalUser {
    pub id: String,
    pub customer_id: String,
    pub contact_id: Option<String>,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
    pub last_login: Option<String>,
    pub role: String,  // 'admin', 'member', or 'viewer'
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePortalUserRequest {
    pub contact_id: Option<String>,
    pub email: String,
    pub password: String,
    #[serde(default = "default_portal_role")]
    pub role: String,
}

fn default_portal_role() -> String {
    "member".to_string()
}

// ============================================================================
// Customer Operations
// ============================================================================

pub async fn create_customer(pool: &SqlitePool, user_id: &str, req: CreateCustomerRequest) -> Result<Customer> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let status = req.status.unwrap_or_else(|| "active".to_string());

    sqlx::query(
        r#"
        INSERT INTO customers (id, user_id, name, industry, company_size, website, address, notes, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.industry)
    .bind(&req.company_size)
    .bind(&req.website)
    .bind(&req.address)
    .bind(&req.notes)
    .bind(&status)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_customer_by_id(pool, &id).await
}

pub async fn get_customer_by_id(pool: &SqlitePool, id: &str) -> Result<Customer> {
    let customer = sqlx::query_as::<_, Customer>("SELECT * FROM customers WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(customer)
}

pub async fn get_user_customers(pool: &SqlitePool, user_id: &str, status: Option<&str>) -> Result<Vec<Customer>> {
    let customers = if let Some(status) = status {
        sqlx::query_as::<_, Customer>(
            "SELECT * FROM customers WHERE user_id = ? AND status = ? ORDER BY name ASC"
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Customer>(
            "SELECT * FROM customers WHERE user_id = ? ORDER BY name ASC"
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };
    Ok(customers)
}

pub async fn update_customer(pool: &SqlitePool, id: &str, user_id: &str, req: UpdateCustomerRequest) -> Result<Customer> {
    // First verify ownership
    let existing = get_customer_by_id(pool, id).await?;
    if existing.user_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to update this customer"));
    }

    let now = Utc::now().to_rfc3339();
    let name = req.name.unwrap_or(existing.name);
    let industry = req.industry.or(existing.industry);
    let company_size = req.company_size.or(existing.company_size);
    let website = req.website.or(existing.website);
    let address = req.address.or(existing.address);
    let notes = req.notes.or(existing.notes);
    let status = req.status.unwrap_or(existing.status);

    sqlx::query(
        r#"
        UPDATE customers SET name = ?, industry = ?, company_size = ?, website = ?, address = ?, notes = ?, status = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&name)
    .bind(&industry)
    .bind(&company_size)
    .bind(&website)
    .bind(&address)
    .bind(&notes)
    .bind(&status)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_customer_by_id(pool, id).await
}

pub async fn delete_customer(pool: &SqlitePool, id: &str, user_id: &str) -> Result<()> {
    let existing = get_customer_by_id(pool, id).await?;
    if existing.user_id != user_id {
        return Err(anyhow::anyhow!("Not authorized to delete this customer"));
    }

    sqlx::query("DELETE FROM customers WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Contact Operations
// ============================================================================

pub async fn create_contact(pool: &SqlitePool, customer_id: &str, req: CreateContactRequest) -> Result<Contact> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let is_primary = req.is_primary.unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO contacts (id, customer_id, first_name, last_name, email, phone, title, is_primary, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.first_name)
    .bind(&req.last_name)
    .bind(&req.email)
    .bind(&req.phone)
    .bind(&req.title)
    .bind(is_primary)
    .bind(&req.notes)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_contact_by_id(pool, &id).await
}

pub async fn get_contact_by_id(pool: &SqlitePool, id: &str) -> Result<Contact> {
    let contact = sqlx::query_as::<_, Contact>("SELECT * FROM contacts WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(contact)
}

pub async fn get_customer_contacts(pool: &SqlitePool, customer_id: &str) -> Result<Vec<Contact>> {
    let contacts = sqlx::query_as::<_, Contact>(
        "SELECT * FROM contacts WHERE customer_id = ? ORDER BY is_primary DESC, last_name ASC"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;
    Ok(contacts)
}

pub async fn update_contact(pool: &SqlitePool, id: &str, req: UpdateContactRequest) -> Result<Contact> {
    let existing = get_contact_by_id(pool, id).await?;
    let now = Utc::now().to_rfc3339();

    let first_name = req.first_name.unwrap_or(existing.first_name);
    let last_name = req.last_name.unwrap_or(existing.last_name);
    let email = req.email.or(existing.email);
    let phone = req.phone.or(existing.phone);
    let title = req.title.or(existing.title);
    let is_primary = req.is_primary.unwrap_or(existing.is_primary);
    let notes = req.notes.or(existing.notes);

    sqlx::query(
        r#"
        UPDATE contacts SET first_name = ?, last_name = ?, email = ?, phone = ?, title = ?, is_primary = ?, notes = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&first_name)
    .bind(&last_name)
    .bind(&email)
    .bind(&phone)
    .bind(&title)
    .bind(is_primary)
    .bind(&notes)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_contact_by_id(pool, id).await
}

pub async fn delete_contact(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM contacts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Engagement Operations
// ============================================================================

pub async fn create_engagement(pool: &SqlitePool, customer_id: &str, req: CreateEngagementRequest) -> Result<Engagement> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let status = req.status.unwrap_or_else(|| "planning".to_string());

    sqlx::query(
        r#"
        INSERT INTO engagements (id, customer_id, name, engagement_type, status, scope, start_date, end_date, budget, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.name)
    .bind(&req.engagement_type)
    .bind(&status)
    .bind(&req.scope)
    .bind(&req.start_date)
    .bind(&req.end_date)
    .bind(&req.budget)
    .bind(&req.notes)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_engagement_by_id(pool, &id).await
}

pub async fn get_engagement_by_id(pool: &SqlitePool, id: &str) -> Result<Engagement> {
    let engagement = sqlx::query_as::<_, Engagement>("SELECT * FROM engagements WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(engagement)
}

pub async fn get_customer_engagements(pool: &SqlitePool, customer_id: &str, status: Option<&str>) -> Result<Vec<Engagement>> {
    let engagements = if let Some(status) = status {
        sqlx::query_as::<_, Engagement>(
            "SELECT * FROM engagements WHERE customer_id = ? AND status = ? ORDER BY created_at DESC"
        )
        .bind(customer_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Engagement>(
            "SELECT * FROM engagements WHERE customer_id = ? ORDER BY created_at DESC"
        )
        .bind(customer_id)
        .fetch_all(pool)
        .await?
    };
    Ok(engagements)
}

pub async fn get_all_engagements(pool: &SqlitePool, user_id: &str, status: Option<&str>) -> Result<Vec<Engagement>> {
    let engagements = if let Some(status) = status {
        sqlx::query_as::<_, Engagement>(
            r#"
            SELECT e.* FROM engagements e
            INNER JOIN customers c ON e.customer_id = c.id
            WHERE c.user_id = ? AND e.status = ?
            ORDER BY e.created_at DESC
            "#
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Engagement>(
            r#"
            SELECT e.* FROM engagements e
            INNER JOIN customers c ON e.customer_id = c.id
            WHERE c.user_id = ?
            ORDER BY e.created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };
    Ok(engagements)
}

pub async fn update_engagement(pool: &SqlitePool, id: &str, req: UpdateEngagementRequest) -> Result<Engagement> {
    let existing = get_engagement_by_id(pool, id).await?;
    let now = Utc::now().to_rfc3339();

    let name = req.name.unwrap_or(existing.name);
    let engagement_type = req.engagement_type.unwrap_or(existing.engagement_type);
    let status = req.status.unwrap_or(existing.status);
    let scope = req.scope.or(existing.scope);
    let start_date = req.start_date.or(existing.start_date);
    let end_date = req.end_date.or(existing.end_date);
    let budget = req.budget.or(existing.budget);
    let notes = req.notes.or(existing.notes);

    sqlx::query(
        r#"
        UPDATE engagements SET name = ?, engagement_type = ?, status = ?, scope = ?, start_date = ?, end_date = ?, budget = ?, notes = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&name)
    .bind(&engagement_type)
    .bind(&status)
    .bind(&scope)
    .bind(&start_date)
    .bind(&end_date)
    .bind(&budget)
    .bind(&notes)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_engagement_by_id(pool, id).await
}

pub async fn delete_engagement(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM engagements WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Milestone Operations
// ============================================================================

pub async fn create_milestone(pool: &SqlitePool, engagement_id: &str, req: CreateMilestoneRequest) -> Result<EngagementMilestone> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let status = req.status.unwrap_or_else(|| "pending".to_string());

    sqlx::query(
        r#"
        INSERT INTO engagement_milestones (id, engagement_id, name, description, due_date, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(engagement_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.due_date)
    .bind(&status)
    .bind(&now)
    .execute(pool)
    .await?;

    get_milestone_by_id(pool, &id).await
}

pub async fn get_milestone_by_id(pool: &SqlitePool, id: &str) -> Result<EngagementMilestone> {
    let milestone = sqlx::query_as::<_, EngagementMilestone>("SELECT * FROM engagement_milestones WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(milestone)
}

pub async fn get_engagement_milestones(pool: &SqlitePool, engagement_id: &str) -> Result<Vec<EngagementMilestone>> {
    let milestones = sqlx::query_as::<_, EngagementMilestone>(
        "SELECT * FROM engagement_milestones WHERE engagement_id = ? ORDER BY due_date ASC NULLS LAST"
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;
    Ok(milestones)
}

pub async fn update_milestone(pool: &SqlitePool, id: &str, req: UpdateMilestoneRequest) -> Result<EngagementMilestone> {
    let existing = get_milestone_by_id(pool, id).await?;

    let name = req.name.unwrap_or(existing.name);
    let description = req.description.or(existing.description);
    let due_date = req.due_date.or(existing.due_date);
    let status = req.status.unwrap_or(existing.status);
    let completed_at = req.completed_at.or(existing.completed_at);

    sqlx::query(
        r#"
        UPDATE engagement_milestones SET name = ?, description = ?, due_date = ?, status = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&name)
    .bind(&description)
    .bind(&due_date)
    .bind(&status)
    .bind(&completed_at)
    .bind(id)
    .execute(pool)
    .await?;

    get_milestone_by_id(pool, id).await
}

pub async fn delete_milestone(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM engagement_milestones WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Contract Operations
// ============================================================================

pub async fn create_contract(pool: &SqlitePool, customer_id: &str, req: CreateContractRequest) -> Result<Contract> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let status = req.status.unwrap_or_else(|| "draft".to_string());

    sqlx::query(
        r#"
        INSERT INTO contracts (id, customer_id, engagement_id, contract_type, name, value, start_date, end_date, status, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.engagement_id)
    .bind(&req.contract_type)
    .bind(&req.name)
    .bind(&req.value)
    .bind(&req.start_date)
    .bind(&req.end_date)
    .bind(&status)
    .bind(&req.notes)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_contract_by_id(pool, &id).await
}

pub async fn get_contract_by_id(pool: &SqlitePool, id: &str) -> Result<Contract> {
    let contract = sqlx::query_as::<_, Contract>("SELECT * FROM contracts WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(contract)
}

pub async fn get_customer_contracts(pool: &SqlitePool, customer_id: &str) -> Result<Vec<Contract>> {
    let contracts = sqlx::query_as::<_, Contract>(
        "SELECT * FROM contracts WHERE customer_id = ? ORDER BY created_at DESC"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;
    Ok(contracts)
}

pub async fn get_all_contracts(pool: &SqlitePool, user_id: &str, status: Option<&str>) -> Result<Vec<Contract>> {
    let contracts = if let Some(status) = status {
        sqlx::query_as::<_, Contract>(
            r#"
            SELECT ct.* FROM contracts ct
            INNER JOIN customers c ON ct.customer_id = c.id
            WHERE c.user_id = ? AND ct.status = ?
            ORDER BY ct.created_at DESC
            "#
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Contract>(
            r#"
            SELECT ct.* FROM contracts ct
            INNER JOIN customers c ON ct.customer_id = c.id
            WHERE c.user_id = ?
            ORDER BY ct.created_at DESC
            "#
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };
    Ok(contracts)
}

pub async fn update_contract(pool: &SqlitePool, id: &str, req: UpdateContractRequest) -> Result<Contract> {
    let existing = get_contract_by_id(pool, id).await?;
    let now = Utc::now().to_rfc3339();

    let engagement_id = req.engagement_id.or(existing.engagement_id);
    let contract_type = req.contract_type.unwrap_or(existing.contract_type);
    let name = req.name.unwrap_or(existing.name);
    let value = req.value.or(existing.value);
    let start_date = req.start_date.or(existing.start_date);
    let end_date = req.end_date.or(existing.end_date);
    let status = req.status.unwrap_or(existing.status);
    let file_path = req.file_path.or(existing.file_path);
    let notes = req.notes.or(existing.notes);

    sqlx::query(
        r#"
        UPDATE contracts SET engagement_id = ?, contract_type = ?, name = ?, value = ?, start_date = ?, end_date = ?, status = ?, file_path = ?, notes = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&engagement_id)
    .bind(&contract_type)
    .bind(&name)
    .bind(&value)
    .bind(&start_date)
    .bind(&end_date)
    .bind(&status)
    .bind(&file_path)
    .bind(&notes)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    get_contract_by_id(pool, id).await
}

pub async fn delete_contract(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM contracts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// SLA Operations
// ============================================================================

pub async fn create_sla(pool: &SqlitePool, customer_id: Option<&str>, req: CreateSlaRequest) -> Result<SlaDefinition> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let is_template = req.is_template.unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO sla_definitions (id, customer_id, name, description, response_time_critical, response_time_high, response_time_medium, response_time_low, resolution_time_critical, resolution_time_high, resolution_time_medium, resolution_time_low, is_template, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.response_time_critical)
    .bind(&req.response_time_high)
    .bind(&req.response_time_medium)
    .bind(&req.response_time_low)
    .bind(&req.resolution_time_critical)
    .bind(&req.resolution_time_high)
    .bind(&req.resolution_time_medium)
    .bind(&req.resolution_time_low)
    .bind(is_template)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_sla_by_id(pool, &id).await
}

pub async fn get_sla_by_id(pool: &SqlitePool, id: &str) -> Result<SlaDefinition> {
    let sla = sqlx::query_as::<_, SlaDefinition>("SELECT * FROM sla_definitions WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(sla)
}

pub async fn get_sla_templates(pool: &SqlitePool) -> Result<Vec<SlaDefinition>> {
    let slas = sqlx::query_as::<_, SlaDefinition>(
        "SELECT * FROM sla_definitions WHERE is_template = 1 ORDER BY name ASC"
    )
    .fetch_all(pool)
    .await?;
    Ok(slas)
}

pub async fn get_customer_sla(pool: &SqlitePool, customer_id: &str) -> Result<Option<SlaDefinition>> {
    let sla = sqlx::query_as::<_, SlaDefinition>(
        "SELECT * FROM sla_definitions WHERE customer_id = ? AND is_template = 0"
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;
    Ok(sla)
}

pub async fn delete_sla(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sla_definitions WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Time Entry Operations
// ============================================================================

pub async fn create_time_entry(pool: &SqlitePool, engagement_id: &str, user_id: &str, req: CreateTimeEntryRequest) -> Result<TimeEntry> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let billable = req.billable.unwrap_or(true);

    sqlx::query(
        r#"
        INSERT INTO time_entries (id, engagement_id, user_id, description, hours, billable, date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(engagement_id)
    .bind(user_id)
    .bind(&req.description)
    .bind(&req.hours)
    .bind(billable)
    .bind(&req.date)
    .bind(&now)
    .execute(pool)
    .await?;

    get_time_entry_by_id(pool, &id).await
}

pub async fn get_time_entry_by_id(pool: &SqlitePool, id: &str) -> Result<TimeEntry> {
    let entry = sqlx::query_as::<_, TimeEntry>("SELECT * FROM time_entries WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(entry)
}

pub async fn get_engagement_time_entries(pool: &SqlitePool, engagement_id: &str) -> Result<Vec<TimeEntry>> {
    let entries = sqlx::query_as::<_, TimeEntry>(
        "SELECT * FROM time_entries WHERE engagement_id = ? ORDER BY date DESC"
    )
    .bind(engagement_id)
    .fetch_all(pool)
    .await?;
    Ok(entries)
}

pub async fn get_user_time_entries(pool: &SqlitePool, user_id: &str, start_date: Option<&str>, end_date: Option<&str>) -> Result<Vec<TimeEntry>> {
    let entries = match (start_date, end_date) {
        (Some(start), Some(end)) => {
            sqlx::query_as::<_, TimeEntry>(
                "SELECT * FROM time_entries WHERE user_id = ? AND date >= ? AND date <= ? ORDER BY date DESC"
            )
            .bind(user_id)
            .bind(start)
            .bind(end)
            .fetch_all(pool)
            .await?
        }
        _ => {
            sqlx::query_as::<_, TimeEntry>(
                "SELECT * FROM time_entries WHERE user_id = ? ORDER BY date DESC LIMIT 100"
            )
            .bind(user_id)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(entries)
}

pub async fn delete_time_entry(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM time_entries WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Communication Operations
// ============================================================================

pub async fn create_communication(pool: &SqlitePool, customer_id: &str, user_id: &str, req: CreateCommunicationRequest) -> Result<Communication> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO communications (id, customer_id, engagement_id, contact_id, user_id, comm_type, subject, content, comm_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.engagement_id)
    .bind(&req.contact_id)
    .bind(user_id)
    .bind(&req.comm_type)
    .bind(&req.subject)
    .bind(&req.content)
    .bind(&req.comm_date)
    .bind(&now)
    .execute(pool)
    .await?;

    get_communication_by_id(pool, &id).await
}

pub async fn get_communication_by_id(pool: &SqlitePool, id: &str) -> Result<Communication> {
    let comm = sqlx::query_as::<_, Communication>("SELECT * FROM communications WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(comm)
}

pub async fn get_customer_communications(pool: &SqlitePool, customer_id: &str, limit: Option<i32>) -> Result<Vec<Communication>> {
    let limit = limit.unwrap_or(50);
    let comms = sqlx::query_as::<_, Communication>(
        "SELECT * FROM communications WHERE customer_id = ? ORDER BY comm_date DESC LIMIT ?"
    )
    .bind(customer_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(comms)
}

pub async fn delete_communication(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM communications WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Portal User Operations
// ============================================================================

pub async fn create_portal_user(pool: &SqlitePool, customer_id: &str, req: CreatePortalUserRequest) -> Result<PortalUser> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Hash the password
    let password_hash = bcrypt::hash(&req.password, crate::db::BCRYPT_COST.clone())
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

    // Validate role
    let role = match req.role.as_str() {
        "admin" | "member" | "viewer" => req.role.clone(),
        _ => "member".to_string(),
    };

    sqlx::query(
        r#"
        INSERT INTO portal_users (id, customer_id, contact_id, email, password_hash, is_active, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(customer_id)
    .bind(&req.contact_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&role)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    get_portal_user_by_id(pool, &id).await
}

pub async fn get_portal_user_by_id(pool: &SqlitePool, id: &str) -> Result<PortalUser> {
    let user = sqlx::query_as::<_, PortalUser>("SELECT * FROM portal_users WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(user)
}

pub async fn get_portal_user_by_email(pool: &SqlitePool, email: &str) -> Result<Option<PortalUser>> {
    let user = sqlx::query_as::<_, PortalUser>("SELECT * FROM portal_users WHERE email = ?")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(user)
}

pub async fn get_customer_portal_users(pool: &SqlitePool, customer_id: &str) -> Result<Vec<PortalUser>> {
    let users = sqlx::query_as::<_, PortalUser>(
        "SELECT * FROM portal_users WHERE customer_id = ? ORDER BY email ASC"
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;
    Ok(users)
}

pub async fn update_portal_user_last_login(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE portal_users SET last_login = ?, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn deactivate_portal_user(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE portal_users SET is_active = 0, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_portal_user(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM portal_users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn activate_portal_user(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE portal_users SET is_active = 1, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePortalUserRequest {
    pub contact_id: Option<String>,
    pub is_active: Option<bool>,
    pub role: Option<String>,
}

pub async fn update_portal_user(pool: &SqlitePool, id: &str, req: UpdatePortalUserRequest) -> Result<PortalUser> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update
    let mut updates = vec!["updated_at = ?"];
    let mut has_contact = false;
    let mut has_active = false;
    let mut has_role = false;

    if req.contact_id.is_some() {
        updates.push("contact_id = ?");
        has_contact = true;
    }
    if req.is_active.is_some() {
        updates.push("is_active = ?");
        has_active = true;
    }
    if req.role.is_some() {
        updates.push("role = ?");
        has_role = true;
    }

    let query = format!("UPDATE portal_users SET {} WHERE id = ?", updates.join(", "));
    let mut q = sqlx::query(&query).bind(&now);

    if has_contact {
        q = q.bind(&req.contact_id);
    }
    if has_active {
        q = q.bind(req.is_active.unwrap_or(true));
    }
    if has_role {
        // Validate role
        let role = match req.role.as_ref().map(|r| r.as_str()) {
            Some("admin") | Some("member") | Some("viewer") => req.role.clone(),
            _ => Some("member".to_string()),
        };
        q = q.bind(role);
    }

    q.bind(id).execute(pool).await?;

    get_portal_user_by_id(pool, id).await
}

/// Admin-initiated password reset - sets a new password directly
pub async fn admin_reset_portal_user_password(pool: &SqlitePool, id: &str, new_password: &str) -> Result<()> {
    let password_hash = bcrypt::hash(new_password, 12)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE portal_users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&password_hash)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get portal user with linked contact info
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PortalUserWithContact {
    pub id: String,
    pub customer_id: String,
    pub contact_id: Option<String>,
    pub email: String,
    pub is_active: bool,
    pub last_login: Option<String>,
    pub role: String,
    pub created_at: String,
    pub updated_at: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub title: Option<String>,
}

pub async fn get_customer_portal_users_with_contacts(pool: &SqlitePool, customer_id: &str) -> Result<Vec<PortalUserWithContact>> {
    let users = sqlx::query_as::<_, PortalUserWithContact>(
        r#"
        SELECT
            pu.id,
            pu.customer_id,
            pu.contact_id,
            pu.email,
            pu.is_active,
            pu.last_login,
            pu.role,
            pu.created_at,
            pu.updated_at,
            c.first_name,
            c.last_name,
            c.phone,
            c.title
        FROM portal_users pu
        LEFT JOIN contacts c ON c.id = pu.contact_id
        WHERE pu.customer_id = ?
        ORDER BY pu.email ASC
        "#
    )
    .bind(customer_id)
    .fetch_all(pool)
    .await?;

    Ok(users)
}

// ============================================================================
// Dashboard Statistics
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrmDashboardStats {
    pub total_customers: i64,
    pub active_customers: i64,
    pub total_engagements: i64,
    pub active_engagements: i64,
    pub total_contracts_value: f64,
    pub upcoming_milestones: Vec<EngagementMilestone>,
    pub overdue_milestones: i64,
    pub recent_communications: Vec<Communication>,
    pub total_hours_this_month: f64,
    pub billable_hours_this_month: f64,
}

pub async fn get_crm_dashboard_stats(pool: &SqlitePool, user_id: &str) -> Result<CrmDashboardStats> {
    // Get customer counts
    let (total_customers,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM customers WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let (active_customers,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM customers WHERE user_id = ? AND status = 'active'"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get engagement counts
    let (total_engagements,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM engagements e
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ?
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    let (active_engagements,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM engagements e
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ? AND e.status = 'in_progress'
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get total contracts value
    let total_contracts_value: Option<f64> = sqlx::query_scalar(
        r#"
        SELECT CAST(COALESCE(SUM(ct.value), 0) AS REAL) FROM contracts ct
        INNER JOIN customers c ON ct.customer_id = c.id
        WHERE c.user_id = ? AND ct.status = 'active'
        "#
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get upcoming milestones (due within 30 days, not completed)
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let month_from_now = (Utc::now() + chrono::Duration::days(30)).format("%Y-%m-%d").to_string();

    let upcoming_milestones: Vec<EngagementMilestone> = sqlx::query_as(
        r#"
        SELECT m.id, m.engagement_id, m.name, m.description, m.due_date, m.completed_at, m.status, m.created_at
        FROM engagement_milestones m
        INNER JOIN engagements e ON m.engagement_id = e.id
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ? AND m.status IN ('pending', 'in_progress') AND m.due_date IS NOT NULL AND m.due_date <= ?
        ORDER BY m.due_date ASC
        LIMIT 10
        "#
    )
    .bind(user_id)
    .bind(&month_from_now)
    .fetch_all(pool)
    .await?;

    let (overdue_milestones,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM engagement_milestones m
        INNER JOIN engagements e ON m.engagement_id = e.id
        INNER JOIN customers c ON e.customer_id = c.id
        WHERE c.user_id = ? AND m.status IN ('pending', 'in_progress') AND m.due_date IS NOT NULL AND m.due_date < ?
        "#
    )
    .bind(user_id)
    .bind(&today)
    .fetch_one(pool)
    .await?;

    // Get recent communications (last 30 days)
    let recent_communications: Vec<Communication> = sqlx::query_as(
        r#"
        SELECT cm.id, cm.customer_id, cm.engagement_id, cm.contact_id, cm.user_id,
               cm.comm_type, cm.subject, cm.content, cm.comm_date, cm.created_at
        FROM communications cm
        INNER JOIN customers c ON cm.customer_id = c.id
        WHERE c.user_id = ?
        ORDER BY cm.comm_date DESC
        LIMIT 10
        "#
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Get hours this month
    let month_start = Utc::now().format("%Y-%m-01").to_string();

    let total_hours_this_month: Option<f64> = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(hours), 0) AS REAL) FROM time_entries WHERE user_id = ? AND date >= ?"
    )
    .bind(user_id)
    .bind(&month_start)
    .fetch_one(pool)
    .await?;

    let billable_hours_this_month: Option<f64> = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(hours), 0) AS REAL) FROM time_entries WHERE user_id = ? AND date >= ? AND billable = 1"
    )
    .bind(user_id)
    .bind(&month_start)
    .fetch_one(pool)
    .await?;

    Ok(CrmDashboardStats {
        total_customers,
        active_customers,
        total_engagements,
        active_engagements,
        total_contracts_value: total_contracts_value.unwrap_or(0.0),
        upcoming_milestones,
        overdue_milestones,
        recent_communications,
        total_hours_this_month: total_hours_this_month.unwrap_or(0.0),
        billable_hours_this_month: billable_hours_this_month.unwrap_or(0.0),
    })
}

// ============================================================================
// Customer Summary (for detail view)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerSummary {
    pub customer: Customer,
    pub contact_count: i64,
    pub engagement_count: i64,
    pub active_engagement_count: i64,
    pub contract_count: i64,
    pub total_contract_value: f64,
    pub scan_count: i64,
    pub vulnerability_count: i64,
}

pub async fn get_customer_summary(pool: &SqlitePool, customer_id: &str) -> Result<CustomerSummary> {
    let customer = get_customer_by_id(pool, customer_id).await?;

    let (contact_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM contacts WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let (engagement_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let (active_engagement_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM engagements WHERE customer_id = ? AND status = 'in_progress'"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let (contract_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM contracts WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let total_contract_value: Option<f64> = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(value), 0) AS REAL) FROM contracts WHERE customer_id = ? AND status = 'active'"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let (scan_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM scan_results WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    let (vulnerability_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM vulnerability_tracking WHERE customer_id = ?"
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;

    Ok(CustomerSummary {
        customer,
        contact_count,
        engagement_count,
        active_engagement_count,
        contract_count,
        total_contract_value: total_contract_value.unwrap_or(0.0),
        scan_count,
        vulnerability_count,
    })
}

// ============================================================================
// Portal Password Reset Token Operations
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PortalPasswordResetToken {
    pub id: String,
    pub portal_user_id: String,
    pub token_hash: String,
    pub expires_at: String,
    pub used_at: Option<String>,
    pub created_at: String,
}

/// Create a password reset token for a portal user
pub async fn create_password_reset_token(
    pool: &SqlitePool,
    portal_user_id: &str,
    token_hash: &str,
    expires_at: &str,
) -> Result<PortalPasswordResetToken> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // Invalidate any existing tokens for this user
    invalidate_user_reset_tokens(pool, portal_user_id).await?;

    sqlx::query(
        r#"
        INSERT INTO portal_password_reset_tokens (id, portal_user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(portal_user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(&now)
    .execute(pool)
    .await?;

    let token = sqlx::query_as::<_, PortalPasswordResetToken>(
        "SELECT * FROM portal_password_reset_tokens WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(token)
}

/// Find a valid (unexpired, unused) reset token by its hash
pub async fn get_valid_reset_token(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<PortalPasswordResetToken>> {
    let now = Utc::now().to_rfc3339();

    let token = sqlx::query_as::<_, PortalPasswordResetToken>(
        r#"
        SELECT * FROM portal_password_reset_tokens
        WHERE token_hash = ? AND expires_at > ? AND used_at IS NULL
        "#
    )
    .bind(token_hash)
    .bind(&now)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Mark a reset token as used
pub async fn mark_reset_token_used(pool: &SqlitePool, token_id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE portal_password_reset_tokens SET used_at = ? WHERE id = ?")
        .bind(&now)
        .bind(token_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update a portal user's password
pub async fn update_portal_user_password(
    pool: &SqlitePool,
    user_id: &str,
    new_password_hash: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE portal_users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(new_password_hash)
        .bind(&now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Invalidate all existing reset tokens for a user
pub async fn invalidate_user_reset_tokens(pool: &SqlitePool, portal_user_id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE portal_password_reset_tokens SET used_at = ? WHERE portal_user_id = ? AND used_at IS NULL"
    )
    .bind(&now)
    .bind(portal_user_id)
    .execute(pool)
    .await?;

    Ok(())
}
