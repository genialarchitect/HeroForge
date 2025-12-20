//! Database operations for Credential Audits
//!
//! This module provides CRUD operations for credential audit scans and results.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// Data Models
// ============================================================================

/// Credential Audit record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct CredentialAuditRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub status: String,
    pub config_json: String,
    pub total_targets: Option<i64>,
    pub total_attempts: Option<i64>,
    pub successful_logins: Option<i64>,
    pub failed_attempts: Option<i64>,
    pub connection_errors: Option<i64>,
    pub services_tested: Option<String>,
    pub error_message: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub duration_secs: Option<f64>,
    pub created_at: String,
}

/// Credential Audit Target record from database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct CredentialAuditTargetRecord {
    pub id: String,
    pub audit_id: String,
    pub host: String,
    pub port: i64,
    pub service_type: String,
    pub use_ssl: Option<i64>,
    pub path: Option<String>,
    pub successful_credentials: Option<String>,
    pub failed_attempts: Option<i64>,
    pub connection_errors: Option<i64>,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// Request to create a new credential audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCredentialAuditRequest {
    pub name: String,
    pub config: serde_json::Value,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of a credential audit for listing
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct CredentialAuditSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub total_targets: Option<i64>,
    pub successful_logins: Option<i64>,
    pub services_tested: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub duration_secs: Option<f64>,
}

// ============================================================================
// CRUD Operations
// ============================================================================

/// Create a new credential audit
pub async fn create_credential_audit(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateCredentialAuditRequest,
) -> Result<CredentialAuditRecord> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let config_json = serde_json::to_string(&request.config)?;

    sqlx::query(
        r#"
        INSERT INTO credential_audits (id, user_id, name, status, config_json,
                                       customer_id, engagement_id, created_at)
        VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&config_json)
    .bind(&request.customer_id)
    .bind(&request.engagement_id)
    .bind(&now)
    .execute(pool)
    .await?;

    get_credential_audit_by_id(pool, &id, user_id).await
}

/// Get a credential audit by ID
pub async fn get_credential_audit_by_id(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<CredentialAuditRecord> {
    let audit = sqlx::query_as::<_, CredentialAuditRecord>(
        "SELECT * FROM credential_audits WHERE id = ?1 AND user_id = ?2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(audit)
}

/// Get all credential audits for a user
pub async fn get_user_credential_audits(
    pool: &SqlitePool,
    user_id: &str,
    status: Option<&str>,
) -> Result<Vec<CredentialAuditSummary>> {
    let audits = if let Some(status) = status {
        sqlx::query_as::<_, CredentialAuditSummary>(
            r#"
            SELECT id, name, status, total_targets, successful_logins,
                   services_tested, created_at, completed_at, duration_secs
            FROM credential_audits
            WHERE user_id = ?1 AND status = ?2
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(status)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, CredentialAuditSummary>(
            r#"
            SELECT id, name, status, total_targets, successful_logins,
                   services_tested, created_at, completed_at, duration_secs
            FROM credential_audits
            WHERE user_id = ?1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?
    };

    Ok(audits)
}

/// Update credential audit status
pub async fn update_credential_audit_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    if status == "running" {
        sqlx::query("UPDATE credential_audits SET status = ?1, started_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
    } else {
        sqlx::query("UPDATE credential_audits SET status = ?1 WHERE id = ?2")
            .bind(status)
            .bind(id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Update credential audit with results
pub async fn update_credential_audit_results(
    pool: &SqlitePool,
    id: &str,
    total_targets: i32,
    total_attempts: i32,
    successful_logins: i32,
    failed_attempts: i32,
    connection_errors: i32,
    services_tested: &str,
    duration_secs: f64,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE credential_audits SET
            status = 'completed',
            total_targets = ?1,
            total_attempts = ?2,
            successful_logins = ?3,
            failed_attempts = ?4,
            connection_errors = ?5,
            services_tested = ?6,
            duration_secs = ?7,
            completed_at = ?8
        WHERE id = ?9
        "#,
    )
    .bind(total_targets)
    .bind(total_attempts)
    .bind(successful_logins)
    .bind(failed_attempts)
    .bind(connection_errors)
    .bind(services_tested)
    .bind(duration_secs)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update credential audit with error
pub async fn update_credential_audit_error(
    pool: &SqlitePool,
    id: &str,
    error_message: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE credential_audits SET status = 'failed', error_message = ?1, completed_at = ?2 WHERE id = ?3",
    )
    .bind(error_message)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a credential audit
pub async fn delete_credential_audit(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM credential_audits WHERE id = ?1 AND user_id = ?2")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Create credential audit target result
pub async fn create_credential_audit_target(
    pool: &SqlitePool,
    audit_id: &str,
    host: &str,
    port: i32,
    service_type: &str,
    use_ssl: bool,
    path: Option<&str>,
    successful_credentials: Option<&str>,
    failed_attempts: i32,
    connection_errors: i32,
    error_message: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let use_ssl_i = if use_ssl { 1i64 } else { 0i64 };

    sqlx::query(
        r#"
        INSERT INTO credential_audit_targets (id, audit_id, host, port, service_type, use_ssl,
                                              path, successful_credentials, failed_attempts,
                                              connection_errors, error_message, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(audit_id)
    .bind(host)
    .bind(port)
    .bind(service_type)
    .bind(use_ssl_i)
    .bind(path)
    .bind(successful_credentials)
    .bind(failed_attempts)
    .bind(connection_errors)
    .bind(error_message)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get targets for a credential audit
pub async fn get_credential_audit_targets(
    pool: &SqlitePool,
    audit_id: &str,
) -> Result<Vec<CredentialAuditTargetRecord>> {
    let targets = sqlx::query_as::<_, CredentialAuditTargetRecord>(
        "SELECT * FROM credential_audit_targets WHERE audit_id = ?1 ORDER BY created_at",
    )
    .bind(audit_id)
    .fetch_all(pool)
    .await?;

    Ok(targets)
}

/// Get targets with successful credentials
pub async fn get_successful_credential_targets(
    pool: &SqlitePool,
    audit_id: &str,
) -> Result<Vec<CredentialAuditTargetRecord>> {
    let targets = sqlx::query_as::<_, CredentialAuditTargetRecord>(
        r#"
        SELECT * FROM credential_audit_targets
        WHERE audit_id = ?1 AND successful_credentials IS NOT NULL
        ORDER BY created_at
        "#,
    )
    .bind(audit_id)
    .fetch_all(pool)
    .await?;

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request_serialization() {
        let request = CreateCredentialAuditRequest {
            name: "Test Audit".to_string(),
            config: serde_json::json!({
                "targets": [{"host": "192.168.1.1", "port": 22}],
                "default_creds_only": true
            }),
            customer_id: None,
            engagement_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("Test Audit"));
    }
}
