#![allow(dead_code)]

pub mod analytics;
pub mod assets;
pub mod models;
pub mod models_dashboard;
pub mod migrations;

use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use anyhow::Result;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use base64::Engine;
use sha2::{Sha256, Digest};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use rand::RngCore;

/// Configurable bcrypt cost factor (defaults to 12, range 10-16)
/// Set via BCRYPT_COST environment variable
pub static BCRYPT_COST: Lazy<u32> = Lazy::new(|| {
    std::env::var("BCRYPT_COST")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(|cost: u32| {
            if cost < 10 {
                log::warn!("BCRYPT_COST {} is too low, using minimum of 10", cost);
                10
            } else if cost > 16 {
                log::warn!("BCRYPT_COST {} is too high, using maximum of 16", cost);
                16
            } else {
                cost
            }
        })
        .unwrap_or(12)
});

pub async fn init_database(database_url: &str) -> Result<SqlitePool> {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    // Check for encryption key in environment variable
    let encryption_key = std::env::var("DATABASE_ENCRYPTION_KEY").ok();

    // Parse the database URL
    let mut connect_options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true);

    // Apply encryption key if provided via PRAGMA key
    // SQLCipher will encrypt the database with AES-256 using this key
    if let Some(key) = &encryption_key {
        log::info!("Database encryption is ENABLED via DATABASE_ENCRYPTION_KEY");
        connect_options = connect_options.pragma("key", key.clone());

        // Set SQLCipher configuration for maximum security
        // PBKDF2 HMAC SHA512 with 256,000 iterations (FIPS 140-2 compliant)
        connect_options = connect_options
            .pragma("cipher_page_size", "4096")
            .pragma("kdf_iter", "256000")
            .pragma("cipher_hmac_algorithm", "HMAC_SHA512")
            .pragma("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512");
    } else {
        log::warn!("Database encryption is DISABLED. Set DATABASE_ENCRYPTION_KEY environment variable to enable encryption.");
        log::warn!("For production use, it is strongly recommended to enable database encryption.");
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    // Configure SQLite pragmas for optimal performance and reliability
    sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await?;
    sqlx::query("PRAGMA synchronous=NORMAL").execute(&pool).await?;
    sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;
    sqlx::query("PRAGMA busy_timeout=5000").execute(&pool).await?;

    // Run migrations
    run_migrations(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create scan_results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            targets TEXT NOT NULL,
            status TEXT NOT NULL,
            results TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            error_message TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scan_results(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_scans_status ON scan_results(status)")
        .execute(pool)
        .await?;

    // Run admin console migrations
    migrations::run_migrations(pool).await?;

    Ok(())
}

pub async fn create_user(
    pool: &SqlitePool,
    user: &models::CreateUser,
) -> Result<models::User> {
    // Validate email address format
    crate::email_validation::validate_email(&user.email)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Validate password against NIST 800-63B guidelines
    crate::password_validation::validate_password(&user.password)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Validate that user has accepted terms (GDPR requirement)
    if !user.accept_terms {
        return Err(anyhow::anyhow!("You must accept the terms and conditions to create an account"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let password_hash = bcrypt::hash(&user.password, *BCRYPT_COST)?;
    let now = chrono::Utc::now();
    let terms_version = "1.0"; // Current terms version

    let user = sqlx::query_as::<_, models::User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, created_at, is_active, accepted_terms_at, terms_version)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(&password_hash)
    .bind(now)
    .bind(true)
    .bind(now)
    .bind(terms_version)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<models::User>> {
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE username = ?1")
        .bind(username)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

pub async fn get_user_by_id(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Option<models::User>> {
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

    Ok(user)
}

pub async fn update_user_profile(
    pool: &SqlitePool,
    user_id: &str,
    updates: &models::UpdateProfileRequest,
) -> Result<models::User> {
    // Validate email if provided
    if let Some(ref email) = updates.email {
        crate::email_validation::validate_email(email)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // Build dynamic update query
    let mut query = String::from("UPDATE users SET ");
    let mut params: Vec<String> = Vec::new();
    let mut set_clauses: Vec<String> = Vec::new();

    if let Some(ref email) = updates.email {
        set_clauses.push(format!("email = ?{}", params.len() + 1));
        params.push(email.clone());
    }

    if set_clauses.is_empty() {
        // Nothing to update, return current user
        return get_user_by_id(pool, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"));
    }

    query.push_str(&set_clauses.join(", "));
    query.push_str(&format!(" WHERE id = ?{} RETURNING *", params.len() + 1));

    let mut q = sqlx::query_as::<_, models::User>(&query);
    for param in &params {
        q = q.bind(param);
    }
    q = q.bind(user_id);

    let user = q.fetch_one(pool).await?;
    Ok(user)
}

pub async fn update_user_password(
    pool: &SqlitePool,
    user_id: &str,
    password_hash: &str,
) -> Result<()> {
    sqlx::query("UPDATE users SET password_hash = ?1 WHERE id = ?2")
        .bind(password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn create_scan(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    targets: &[String],
) -> Result<models::ScanResult> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();
    let targets_str = serde_json::to_string(targets)?;

    let scan = sqlx::query_as::<_, models::ScanResult>(
        r#"
        INSERT INTO scan_results (id, user_id, name, targets, status, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(&targets_str)
    .bind("pending")
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

pub async fn get_user_scans(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::ScanResult>> {
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

pub async fn get_scan_by_id(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Option<models::ScanResult>> {
    let scan = sqlx::query_as::<_, models::ScanResult>("SELECT * FROM scan_results WHERE id = ?1")
        .bind(scan_id)
        .fetch_optional(pool)
        .await?;

    Ok(scan)
}

pub async fn update_scan_status(
    pool: &SqlitePool,
    scan_id: &str,
    status: &str,
    results: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    let now = chrono::Utc::now();

    if status == "running" {
        sqlx::query("UPDATE scan_results SET status = ?1, started_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(now)
            .bind(scan_id)
            .execute(pool)
            .await?;
    } else if status == "completed" {
        sqlx::query(
            "UPDATE scan_results SET status = ?1, results = ?2, completed_at = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(results)
        .bind(now)
        .bind(scan_id)
        .execute(pool)
        .await?;
    } else if status == "failed" {
        sqlx::query(
            "UPDATE scan_results SET status = ?1, error_message = ?2, completed_at = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(error)
        .bind(now)
        .bind(scan_id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

// ============================================================================
// Admin Console Database Functions
// ============================================================================

// Role Management

pub async fn get_user_roles(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::Role>> {
    let roles = sqlx::query_as::<_, models::Role>(
        r#"
        SELECT r.* FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?1
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(roles)
}

pub async fn assign_role_to_user(
    pool: &SqlitePool,
    user_id: &str,
    role_id: &str,
    assigned_by: &str,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_at, assigned_by)
        VALUES (?1, ?2, ?3, ?4)
        "#,
    )
    .bind(user_id)
    .bind(role_id)
    .bind(now)
    .bind(assigned_by)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn remove_role_from_user(
    pool: &SqlitePool,
    user_id: &str,
    role_id: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn has_permission(pool: &SqlitePool, user_id: &str, permission: &str) -> Result<bool> {
    let roles = get_user_roles(pool, user_id).await?;

    for role in roles {
        let has_perm = match permission {
            "manage_users" => role.can_manage_users,
            "manage_scans" => role.can_manage_scans,
            "view_all_scans" => role.can_view_all_scans,
            "delete_any_scan" => role.can_delete_any_scan,
            "view_audit_logs" => role.can_view_audit_logs,
            "manage_settings" => role.can_manage_settings,
            _ => false,
        };

        if has_perm {
            return Ok(true);
        }
    }

    Ok(false)
}

// User Management (Admin)

pub async fn get_all_users(pool: &SqlitePool) -> Result<Vec<models::User>> {
    let users = sqlx::query_as::<_, models::User>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;

    Ok(users)
}

pub async fn update_user(
    pool: &SqlitePool,
    user_id: &str,
    updates: &models::UpdateUserRequest,
) -> Result<models::User> {
    // Validate email if provided
    if let Some(ref email) = updates.email {
        crate::email_validation::validate_email(email)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    if let Some(email) = &updates.email {
        sqlx::query("UPDATE users SET email = ?1 WHERE id = ?2")
            .bind(email)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(is_active) = updates.is_active {
        sqlx::query("UPDATE users SET is_active = ?1 WHERE id = ?2")
            .bind(is_active)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    Ok(user)
}

pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// Scan Management (Admin)

pub async fn get_all_scans(pool: &SqlitePool) -> Result<Vec<models::ScanResult>> {
    let scans = sqlx::query_as::<_, models::ScanResult>(
        "SELECT * FROM scan_results ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

pub async fn delete_scan_admin(pool: &SqlitePool, scan_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scan_results WHERE id = ?1")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete a scan (user-level, verifies ownership)
pub async fn delete_scan(pool: &SqlitePool, scan_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM scan_results WHERE id = ?1 AND user_id = ?2")
        .bind(scan_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// Audit Logging

pub async fn create_audit_log(pool: &SqlitePool, log: &models::AuditLog) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs (id, user_id, action, target_type, target_id, details, ip_address, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&log.id)
    .bind(&log.user_id)
    .bind(&log.action)
    .bind(&log.target_type)
    .bind(&log.target_id)
    .bind(&log.details)
    .bind(&log.ip_address)
    .bind(&log.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_audit_logs(
    pool: &SqlitePool,
    limit: i64,
    offset: i64,
) -> Result<Vec<models::AuditLog>> {
    let logs = sqlx::query_as::<_, models::AuditLog>(
        "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

// System Settings

pub async fn get_all_settings(pool: &SqlitePool) -> Result<Vec<models::SystemSetting>> {
    let settings = sqlx::query_as::<_, models::SystemSetting>(
        "SELECT * FROM system_settings ORDER BY key",
    )
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

pub async fn get_setting(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<models::SystemSetting>> {
    let setting = sqlx::query_as::<_, models::SystemSetting>(
        "SELECT * FROM system_settings WHERE key = ?1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    Ok(setting)
}

pub async fn update_setting(
    pool: &SqlitePool,
    key: &str,
    value: &str,
    updated_by: &str,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        "UPDATE system_settings SET value = ?1, updated_by = ?2, updated_at = ?3 WHERE key = ?4",
    )
    .bind(value)
    .bind(updated_by)
    .bind(now)
    .bind(key)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Report Management Functions
// ============================================================================

/// Create a new report record
pub async fn create_report(
    pool: &SqlitePool,
    user_id: &str,
    scan_id: &str,
    name: &str,
    description: Option<&str>,
    format: &str,
    template_id: &str,
    sections: &[String],
    metadata: Option<&str>,
) -> Result<models::Report> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let sections_json = serde_json::to_string(sections)?;

    let report = sqlx::query_as::<_, models::Report>(
        r#"
        INSERT INTO reports (id, user_id, scan_id, name, description, format, template_id, sections, status, metadata, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(scan_id)
    .bind(name)
    .bind(description)
    .bind(format)
    .bind(template_id)
    .bind(&sections_json)
    .bind("pending")
    .bind(metadata)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(report)
}

/// Get all reports for a user
pub async fn get_user_reports(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Get reports for a specific scan
pub async fn get_scan_reports(pool: &SqlitePool, scan_id: &str) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports WHERE scan_id = ?1 ORDER BY created_at DESC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

/// Get a report by ID
pub async fn get_report_by_id(pool: &SqlitePool, report_id: &str) -> Result<Option<models::Report>> {
    let report = sqlx::query_as::<_, models::Report>("SELECT * FROM reports WHERE id = ?1")
        .bind(report_id)
        .fetch_optional(pool)
        .await?;

    Ok(report)
}

/// Update report status (generating, completed, failed)
pub async fn update_report_status(
    pool: &SqlitePool,
    report_id: &str,
    status: &str,
    file_path: Option<&str>,
    file_size: Option<i64>,
    error: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    match status {
        "generating" => {
            sqlx::query("UPDATE reports SET status = ?1 WHERE id = ?2")
                .bind(status)
                .bind(report_id)
                .execute(pool)
                .await?;
        }
        "completed" => {
            sqlx::query(
                "UPDATE reports SET status = ?1, file_path = ?2, file_size = ?3, completed_at = ?4 WHERE id = ?5",
            )
            .bind(status)
            .bind(file_path)
            .bind(file_size)
            .bind(now)
            .bind(report_id)
            .execute(pool)
            .await?;
        }
        "failed" => {
            sqlx::query(
                "UPDATE reports SET status = ?1, error_message = ?2, completed_at = ?3 WHERE id = ?4",
            )
            .bind(status)
            .bind(error)
            .bind(now)
            .bind(report_id)
            .execute(pool)
            .await?;
        }
        _ => {}
    }

    Ok(())
}

/// Delete a report
pub async fn delete_report(pool: &SqlitePool, report_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM reports WHERE id = ?1")
        .bind(report_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all reports (admin)
pub async fn get_all_reports(pool: &SqlitePool) -> Result<Vec<models::Report>> {
    let reports = sqlx::query_as::<_, models::Report>(
        "SELECT * FROM reports ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(reports)
}

// ============================================================================
// Scan Template Management Functions
// ============================================================================

/// Create a new scan template
pub async fn create_template(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateTemplateRequest,
) -> Result<models::ScanTemplate> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(&request.config)?;

    let template = sqlx::query_as::<_, models::ScanTemplate>(
        r#"
        INSERT INTO scan_templates (id, user_id, name, description, config, is_default, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&config_json)
    .bind(request.is_default)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(template)
}

/// Get all templates for a user
pub async fn get_user_templates(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::ScanTemplate>> {
    let templates = sqlx::query_as::<_, models::ScanTemplate>(
        "SELECT * FROM scan_templates WHERE user_id = ?1 ORDER BY is_default DESC, created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(templates)
}

/// Get a template by ID
pub async fn get_template_by_id(pool: &SqlitePool, template_id: &str) -> Result<Option<models::ScanTemplate>> {
    let template = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_optional(pool)
        .await?;

    Ok(template)
}

/// Update a template
pub async fn update_template(
    pool: &SqlitePool,
    template_id: &str,
    request: &models::UpdateTemplateRequest,
) -> Result<models::ScanTemplate> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE scan_templates SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE scan_templates SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(config) = &request.config {
        let config_json = serde_json::to_string(config)?;
        sqlx::query("UPDATE scan_templates SET config = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&config_json)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    if let Some(is_default) = request.is_default {
        sqlx::query("UPDATE scan_templates SET is_default = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(is_default)
            .bind(now)
            .bind(template_id)
            .execute(pool)
            .await?;
    }

    let template = sqlx::query_as::<_, models::ScanTemplate>("SELECT * FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .fetch_one(pool)
        .await?;

    Ok(template)
}

/// Delete a template
pub async fn delete_template(pool: &SqlitePool, template_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scan_templates WHERE id = ?1")
        .bind(template_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Target Group Management Functions
// ============================================================================

/// Create a new target group
pub async fn create_target_group(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateTargetGroupRequest,
) -> Result<models::TargetGroup> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let targets_json = serde_json::to_string(&request.targets)?;

    let group = sqlx::query_as::<_, models::TargetGroup>(
        r#"
        INSERT INTO target_groups (id, user_id, name, description, targets, color, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&targets_json)
    .bind(&request.color)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Get all target groups for a user
pub async fn get_user_target_groups(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::TargetGroup>> {
    let groups = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(groups)
}

/// Get a target group by ID
pub async fn get_target_group_by_id(
    pool: &SqlitePool,
    group_id: &str,
) -> Result<Option<models::TargetGroup>> {
    let group = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE id = ?1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?;

    Ok(group)
}

/// Update a target group
pub async fn update_target_group(
    pool: &SqlitePool,
    group_id: &str,
    request: &models::UpdateTargetGroupRequest,
) -> Result<models::TargetGroup> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE target_groups SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = &request.description {
        sqlx::query("UPDATE target_groups SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(targets) = &request.targets {
        let targets_json = serde_json::to_string(targets)?;
        sqlx::query("UPDATE target_groups SET targets = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&targets_json)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    if let Some(color) = &request.color {
        sqlx::query("UPDATE target_groups SET color = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(color)
            .bind(now)
            .bind(group_id)
            .execute(pool)
            .await?;
    }

    let group = sqlx::query_as::<_, models::TargetGroup>(
        "SELECT * FROM target_groups WHERE id = ?1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;

    Ok(group)
}

/// Delete a target group
pub async fn delete_target_group(pool: &SqlitePool, group_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM target_groups WHERE id = ?1")
        .bind(group_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Scheduled Scans Functions
// ============================================================================

/// Create a new scheduled scan
pub async fn create_scheduled_scan(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateScheduledScanRequest,
) -> Result<models::ScheduledScan> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let config_json = serde_json::to_string(&request.config)?;
    let next_run_at = calculate_next_run(&request.schedule_type, &request.schedule_value)?;

    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        INSERT INTO scheduled_scans (id, user_id, name, description, config, schedule_type, schedule_value, next_run_at, is_active, run_count, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 0, ?9, ?10)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&config_json)
    .bind(&request.schedule_type)
    .bind(&request.schedule_value)
    .bind(next_run_at)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Get all scheduled scans for a user
pub async fn get_user_scheduled_scans(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<models::ScheduledScan>> {
    let scans = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Get a scheduled scan by ID
pub async fn get_scheduled_scan_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<models::ScheduledScan>> {
    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(scan)
}

/// Update a scheduled scan
pub async fn update_scheduled_scan(
    pool: &SqlitePool,
    id: &str,
    request: &models::UpdateScheduledScanRequest,
) -> Result<models::ScheduledScan> {
    let now = Utc::now();

    // Fetch current scan to merge updates
    let current = get_scheduled_scan_by_id(pool, id).await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled scan not found"))?;

    let name = request.name.as_ref().unwrap_or(&current.name);
    let description = request.description.clone().or(current.description);
    let config = request.config.as_ref()
        .map(|c| serde_json::to_string(c).unwrap_or_default())
        .unwrap_or(current.config);
    let schedule_type = request.schedule_type.as_ref().unwrap_or(&current.schedule_type);
    let schedule_value = request.schedule_value.as_ref().unwrap_or(&current.schedule_value);
    let is_active = request.is_active.unwrap_or(current.is_active);

    // Recalculate next_run_at if schedule changed
    let next_run_at = if request.schedule_type.is_some() || request.schedule_value.is_some() {
        calculate_next_run(schedule_type, schedule_value)?
    } else {
        current.next_run_at
    };

    let scan = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        UPDATE scheduled_scans
        SET name = ?1, description = ?2, config = ?3, schedule_type = ?4,
            schedule_value = ?5, is_active = ?6, next_run_at = ?7, updated_at = ?8
        WHERE id = ?9
        RETURNING *
        "#,
    )
    .bind(name)
    .bind(&description)
    .bind(&config)
    .bind(schedule_type)
    .bind(schedule_value)
    .bind(is_active)
    .bind(next_run_at)
    .bind(now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(scan)
}

/// Delete a scheduled scan
pub async fn delete_scheduled_scan(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM scheduled_scans WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all scheduled scans that are due to run (next_run_at <= now and is_active = true)
pub async fn get_due_scheduled_scans(pool: &SqlitePool) -> Result<Vec<models::ScheduledScan>> {
    let now = Utc::now();
    let scans = sqlx::query_as::<_, models::ScheduledScan>(
        "SELECT * FROM scheduled_scans WHERE is_active = 1 AND next_run_at <= ?1 ORDER BY next_run_at ASC",
    )
    .bind(now)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update a scheduled scan after execution
pub async fn update_scheduled_scan_execution(
    pool: &SqlitePool,
    id: &str,
    scan_id: &str,
) -> Result<models::ScheduledScan> {
    // Get the current scheduled scan to calculate next run
    let current = get_scheduled_scan_by_id(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Scheduled scan not found"))?;

    let now = Utc::now();
    let next_run = calculate_next_run(&current.schedule_type, &current.schedule_value)?;
    let new_run_count = current.run_count + 1;

    let updated = sqlx::query_as::<_, models::ScheduledScan>(
        r#"
        UPDATE scheduled_scans
        SET last_run_at = ?1, last_scan_id = ?2, run_count = ?3, next_run_at = ?4, updated_at = ?5
        WHERE id = ?6
        RETURNING *
        "#,
    )
    .bind(now)
    .bind(scan_id)
    .bind(new_run_count)
    .bind(next_run)
    .bind(now)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Helper function for schedule calculation
fn calculate_next_run(schedule_type: &str, schedule_value: &str) -> Result<DateTime<Utc>> {
    use chrono::{Duration, NaiveTime};

    let now = Utc::now();

    match schedule_type {
        "daily" => {
            // schedule_value format: "HH:MM" (e.g., "02:00")
            let time = NaiveTime::parse_from_str(schedule_value, "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format, expected HH:MM"))?;
            let mut next = now.date_naive().and_time(time).and_utc();
            if next <= now {
                next = next + Duration::days(1);
            }
            Ok(next)
        }
        "weekly" => {
            // schedule_value format: "DAY HH:MM" (e.g., "monday 02:00")
            let parts: Vec<&str> = schedule_value.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid weekly format, expected 'DAY HH:MM'"));
            }
            let _day = parts[0].to_lowercase();
            let time = NaiveTime::parse_from_str(parts[1], "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format"))?;
            // Simplified: just add 7 days from now at the specified time
            let next = now.date_naive().and_time(time).and_utc() + Duration::days(7);
            Ok(next)
        }
        "monthly" => {
            // schedule_value format: "DD HH:MM" (e.g., "01 02:00" for 1st of month)
            let parts: Vec<&str> = schedule_value.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid monthly format, expected 'DD HH:MM'"));
            }
            let time = NaiveTime::parse_from_str(parts[1], "%H:%M")
                .map_err(|_| anyhow::anyhow!("Invalid time format"))?;
            // Simplified: add 30 days
            let next = now.date_naive().and_time(time).and_utc() + Duration::days(30);
            Ok(next)
        }
        _ => {
            // Default: run in 24 hours
            Ok(now + Duration::days(1))
        }
    }
}

// ============================================================================
// Scheduled Scan Execution History Functions
// ============================================================================

/// Create a new execution history record
pub async fn create_execution_record(
    pool: &SqlitePool,
    scheduled_scan_id: &str,
    retry_attempt: i32,
) -> Result<models::ScheduledScanExecution> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let record = sqlx::query_as::<_, models::ScheduledScanExecution>(
        r#"
        INSERT INTO scheduled_scan_executions (id, scheduled_scan_id, started_at, status, retry_attempt)
        VALUES (?1, ?2, ?3, 'running', ?4)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(scheduled_scan_id)
    .bind(now)
    .bind(retry_attempt)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// Update an execution record when scan completes
pub async fn complete_execution_record(
    pool: &SqlitePool,
    execution_id: &str,
    scan_result_id: Option<&str>,
    status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scan_executions
        SET scan_result_id = ?1, completed_at = ?2, status = ?3, error_message = ?4
        WHERE id = ?5
        "#,
    )
    .bind(scan_result_id)
    .bind(now)
    .bind(status)
    .bind(error_message)
    .bind(execution_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get execution history for a scheduled scan (limited to last 50 entries)
pub async fn get_execution_history(
    pool: &SqlitePool,
    scheduled_scan_id: &str,
) -> Result<Vec<models::ScheduledScanExecution>> {
    let records = sqlx::query_as::<_, models::ScheduledScanExecution>(
        r#"
        SELECT * FROM scheduled_scan_executions
        WHERE scheduled_scan_id = ?1
        ORDER BY started_at DESC
        LIMIT 50
        "#,
    )
    .bind(scheduled_scan_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// Clean up old execution records (keep last 50 per scheduled scan)
pub async fn cleanup_old_executions(pool: &SqlitePool, scheduled_scan_id: &str) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM scheduled_scan_executions
        WHERE id IN (
            SELECT id FROM scheduled_scan_executions
            WHERE scheduled_scan_id = ?1
            ORDER BY started_at DESC
            LIMIT -1 OFFSET 50
        )
        "#,
    )
    .bind(scheduled_scan_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update scheduled scan retry count and error message
pub async fn update_scheduled_scan_retry(
    pool: &SqlitePool,
    id: &str,
    retry_count: i32,
    last_error: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET retry_count = ?1, last_error = ?2, updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(retry_count)
    .bind(last_error)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Reset retry count on successful execution
pub async fn reset_scheduled_scan_retry(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE scheduled_scans
        SET retry_count = 0, last_error = NULL, updated_at = ?1
        WHERE id = ?2
        "#,
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Notification Settings Functions
// ============================================================================

/// Get notification settings for a user (creates default if not exists)
pub async fn get_notification_settings(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<models::NotificationSettings> {
    // Try to get existing settings
    if let Some(settings) = sqlx::query_as::<_, models::NotificationSettings>(
        "SELECT * FROM notification_settings WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    {
        return Ok(settings);
    }

    // If not exists, get user email and create default settings
    let user = sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_one(pool)
        .await?;

    let now = Utc::now();
    let settings = sqlx::query_as::<_, models::NotificationSettings>(
        r#"
        INSERT INTO notification_settings (user_id, email_on_scan_complete, email_on_critical_vuln, email_address, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(false) // Default: don't send on scan complete
    .bind(true)  // Default: send on critical vulnerabilities
    .bind(&user.email)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Update notification settings for a user
pub async fn update_notification_settings(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::UpdateNotificationSettingsRequest,
) -> Result<models::NotificationSettings> {
    // Validate email if provided
    if let Some(ref email_address) = request.email_address {
        crate::email_validation::validate_email(email_address)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    let now = Utc::now();

    // Ensure settings exist first
    let _ = get_notification_settings(pool, user_id).await?;

    if let Some(email_on_scan_complete) = request.email_on_scan_complete {
        sqlx::query(
            "UPDATE notification_settings SET email_on_scan_complete = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_on_scan_complete)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(email_on_critical_vuln) = request.email_on_critical_vuln {
        sqlx::query(
            "UPDATE notification_settings SET email_on_critical_vuln = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_on_critical_vuln)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(email_address) = &request.email_address {
        sqlx::query(
            "UPDATE notification_settings SET email_address = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(email_address)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(ref slack_webhook_url) = request.slack_webhook_url {
        sqlx::query(
            "UPDATE notification_settings SET slack_webhook_url = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(slack_webhook_url)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(ref teams_webhook_url) = request.teams_webhook_url {
        sqlx::query(
            "UPDATE notification_settings SET teams_webhook_url = ?1, updated_at = ?2 WHERE user_id = ?3",
        )
        .bind(teams_webhook_url)
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    let settings = sqlx::query_as::<_, models::NotificationSettings>(
        "SELECT * FROM notification_settings WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

// ============================================================================
// Vulnerability Management Functions
// ============================================================================

/// Create vulnerability tracking record
pub async fn create_vulnerability_tracking(
    pool: &SqlitePool,
    scan_id: &str,
    host_ip: &str,
    port: Option<i32>,
    vulnerability_id: &str,
    severity: &str,
) -> Result<models::VulnerabilityTracking> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let vuln = sqlx::query_as::<_, models::VulnerabilityTracking>(
        r#"
        INSERT INTO vulnerability_tracking
        (id, scan_id, host_ip, port, vulnerability_id, severity, status, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(host_ip)
    .bind(port)
    .bind(vulnerability_id)
    .bind(severity)
    .bind("open")
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(vuln)
}

/// Get vulnerability tracking records by scan ID with optional filters
pub async fn get_vulnerability_tracking_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
    status: Option<&str>,
    severity: Option<&str>,
) -> Result<Vec<models::VulnerabilityTracking>> {
    let mut query = String::from("SELECT * FROM vulnerability_tracking WHERE scan_id = ?1");
    let mut params = vec![scan_id.to_string()];

    if let Some(s) = status {
        query.push_str(" AND status = ?");
        params.push(s.to_string());
    }

    if let Some(sev) = severity {
        query.push_str(" AND severity = ?");
        params.push(sev.to_string());
    }

    query.push_str(" ORDER BY created_at DESC");

    let mut q = sqlx::query_as::<_, models::VulnerabilityTracking>(&query);
    for param in &params {
        q = q.bind(param);
    }

    let vulnerabilities = q.fetch_all(pool).await?;
    Ok(vulnerabilities)
}

/// Get single vulnerability with details
pub async fn get_vulnerability_detail(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<models::VulnerabilityDetail> {
    let vulnerability = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    // Get comments with user information
    let comments = sqlx::query_as::<_, models::VulnerabilityCommentWithUser>(
        r#"
        SELECT
            vc.id,
            vc.vulnerability_tracking_id,
            vc.user_id,
            u.username,
            vc.comment,
            vc.created_at
        FROM vulnerability_comments vc
        JOIN users u ON vc.user_id = u.id
        WHERE vc.vulnerability_tracking_id = ?1
        ORDER BY vc.created_at ASC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    // Get assignee info if exists
    let assignee = if let Some(assignee_id) = &vulnerability.assignee_id {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(assignee_id)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get resolved_by info if exists
    let resolved_by_user = if let Some(resolved_by) = &vulnerability.resolved_by {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(resolved_by)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get verified_by info if exists
    let verified_by_user = if let Some(verified_by) = &vulnerability.verified_by {
        sqlx::query_as::<_, models::User>("SELECT * FROM users WHERE id = ?1")
            .bind(verified_by)
            .fetch_optional(pool)
            .await?
            .map(|u| u.into())
    } else {
        None
    };

    // Get timeline events with user information
    let timeline = get_remediation_timeline(pool, vuln_id).await?;

    Ok(models::VulnerabilityDetail {
        vulnerability,
        comments,
        timeline,
        assignee,
        resolved_by_user,
        verified_by_user,
    })
}

/// Get remediation timeline for a vulnerability with user information
pub async fn get_remediation_timeline(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::RemediationTimelineEventWithUser>> {
    let timeline = sqlx::query_as::<_, models::RemediationTimelineEventWithUser>(
        r#"
        SELECT
            rt.id,
            rt.vulnerability_tracking_id,
            rt.user_id,
            u.username,
            rt.event_type,
            rt.old_value,
            rt.new_value,
            rt.comment,
            rt.created_at
        FROM remediation_timeline rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.vulnerability_tracking_id = ?1
        ORDER BY rt.created_at DESC
        "#,
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    Ok(timeline)
}

/// Create timeline events for vulnerability update
async fn create_timeline_events_for_update(
    pool: &SqlitePool,
    vuln_id: &str,
    request: &models::UpdateVulnerabilityRequest,
    user_id: &str,
) -> Result<()> {
    let now = Utc::now();

    // Get current vulnerability state to track changes
    let current = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    // Track status change
    if let Some(new_status) = &request.status {
        if &current.status != new_status {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, created_at)
                VALUES (?1, ?2, ?3, 'status_change', ?4, ?5, ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(&current.status)
            .bind(new_status)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track assignment change
    if let Some(new_assignee) = &request.assignee_id {
        if current.assignee_id.as_ref() != Some(new_assignee) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, created_at)
                VALUES (?1, ?2, ?3, 'assignment', ?4, ?5, ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(current.assignee_id)
            .bind(new_assignee)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track priority change
    if let Some(new_priority) = &request.priority {
        if current.priority.as_ref() != Some(new_priority) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'priority_change', ?4, ?5, 'Priority updated', ?6)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(current.priority)
            .bind(new_priority)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    // Track notes update
    if let Some(new_notes) = &request.notes {
        if current.notes.as_ref() != Some(new_notes) {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, comment, created_at)
                VALUES (?1, ?2, ?3, 'note_added', ?4, ?5)
                "#,
            )
            .bind(&id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(new_notes)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Update vulnerability status and metadata
pub async fn update_vulnerability_status(
    pool: &SqlitePool,
    vuln_id: &str,
    request: &models::UpdateVulnerabilityRequest,
    user_id: &str,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Build update query dynamically based on provided fields
    let mut update_parts = Vec::new();
    let mut param_count = 2;

    update_parts.push("updated_at = ?1".to_string());

    if request.status.is_some() {
        update_parts.push(format!("status = ?{}", param_count));
        param_count += 1;
    }
    if request.assignee_id.is_some() {
        update_parts.push(format!("assignee_id = ?{}", param_count));
        param_count += 1;
    }
    if request.notes.is_some() {
        update_parts.push(format!("notes = ?{}", param_count));
        param_count += 1;
    }
    if request.due_date.is_some() {
        update_parts.push(format!("due_date = ?{}", param_count));
        param_count += 1;
    }
    if request.priority.is_some() {
        update_parts.push(format!("priority = ?{}", param_count));
        param_count += 1;
    }
    if request.remediation_steps.is_some() {
        update_parts.push(format!("remediation_steps = ?{}", param_count));
        param_count += 1;
    }
    if request.estimated_effort.is_some() {
        update_parts.push(format!("estimated_effort = ?{}", param_count));
        param_count += 1;
    }
    if request.actual_effort.is_some() {
        update_parts.push(format!("actual_effort = ?{}", param_count));
        param_count += 1;
    }

    // Check if status is being set to 'resolved'
    if let Some(status) = &request.status {
        if status == "resolved" {
            update_parts.push(format!("resolved_at = ?{}", param_count));
            param_count += 1;
            update_parts.push(format!("resolved_by = ?{}", param_count));
        }
    }

    let query = format!(
        "UPDATE vulnerability_tracking SET {} WHERE id = ?{}",
        update_parts.join(", "),
        param_count
    );

    let mut q = sqlx::query(&query).bind(now);

    if let Some(status) = &request.status {
        q = q.bind(status);
        if status == "resolved" {
            q = q.bind(now).bind(user_id);
        }
    }
    if let Some(assignee_id) = &request.assignee_id {
        q = q.bind(assignee_id);
    }
    if let Some(notes) = &request.notes {
        q = q.bind(notes);
    }
    if let Some(due_date) = &request.due_date {
        q = q.bind(due_date);
    }
    if let Some(priority) = &request.priority {
        q = q.bind(priority);
    }
    if let Some(remediation_steps) = &request.remediation_steps {
        q = q.bind(remediation_steps);
    }
    if let Some(estimated_effort) = &request.estimated_effort {
        q = q.bind(estimated_effort);
    }
    if let Some(actual_effort) = &request.actual_effort {
        q = q.bind(actual_effort);
    }

    q = q.bind(vuln_id);
    q.execute(pool).await?;

    // Create timeline events for the changes
    create_timeline_events_for_update(pool, vuln_id, request, user_id).await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Add comment to vulnerability
pub async fn add_vulnerability_comment(
    pool: &SqlitePool,
    vuln_id: &str,
    user_id: &str,
    comment: &str,
) -> Result<models::VulnerabilityComment> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let comment_record = sqlx::query_as::<_, models::VulnerabilityComment>(
        r#"
        INSERT INTO vulnerability_comments (id, vulnerability_tracking_id, user_id, comment, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(comment)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(comment_record)
}

/// Get comments for a vulnerability
pub async fn get_vulnerability_comments(
    pool: &SqlitePool,
    vuln_id: &str,
) -> Result<Vec<models::VulnerabilityComment>> {
    let comments = sqlx::query_as::<_, models::VulnerabilityComment>(
        "SELECT * FROM vulnerability_comments WHERE vulnerability_tracking_id = ?1 ORDER BY created_at ASC",
    )
    .bind(vuln_id)
    .fetch_all(pool)
    .await?;

    Ok(comments)
}

/// Bulk update vulnerability statuses
pub async fn bulk_update_vulnerability_status(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    status: Option<&str>,
    assignee_id: Option<&str>,
    user_id: &str,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();

    // Use a transaction for bulk updates
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Build query based on what fields are being updated
        let query_str = if let Some(s) = status {
            if s == "resolved" {
                "UPDATE vulnerability_tracking SET updated_at = ?1, status = ?2, resolved_at = ?3, resolved_by = ?4 WHERE id = ?5"
            } else {
                "UPDATE vulnerability_tracking SET updated_at = ?1, status = ?2 WHERE id = ?3"
            }
        } else if assignee_id.is_some() {
            "UPDATE vulnerability_tracking SET updated_at = ?1, assignee_id = ?2 WHERE id = ?3"
        } else {
            "UPDATE vulnerability_tracking SET updated_at = ?1 WHERE id = ?2"
        };

        let mut q = sqlx::query(query_str).bind(now);

        if let Some(s) = status {
            q = q.bind(s);
            if s == "resolved" {
                q = q.bind(now).bind(user_id).bind(vuln_id);
            } else {
                q = q.bind(vuln_id);
            }
        } else if let Some(assignee) = assignee_id {
            q = q.bind(assignee).bind(vuln_id);
        } else {
            q = q.bind(vuln_id);
        }

        let result = q.execute(&mut *tx).await?;
        updated_count += result.rows_affected() as usize;
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Mark vulnerability for verification
pub async fn mark_vulnerability_for_verification(
    pool: &SqlitePool,
    vuln_id: &str,
    scan_id: Option<&str>,
    user_id: &str,
) -> Result<models::VulnerabilityTracking> {
    let now = Utc::now();

    // Update status to pending_verification
    if let Some(sid) = scan_id {
        sqlx::query(
            "UPDATE vulnerability_tracking SET status = 'pending_verification', updated_at = ?1, verification_scan_id = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(sid)
        .bind(vuln_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE vulnerability_tracking SET status = 'pending_verification', updated_at = ?1 WHERE id = ?2",
        )
        .bind(now)
        .bind(vuln_id)
        .execute(pool)
        .await?;
    }

    // Create timeline event
    let event_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
        VALUES (?1, ?2, ?3, 'verification_requested', NULL, ?4, 'Marked for verification', ?5)
        "#,
    )
    .bind(&event_id)
    .bind(vuln_id)
    .bind(user_id)
    .bind(scan_id)
    .bind(now)
    .execute(pool)
    .await?;

    // Return updated vulnerability
    let updated = sqlx::query_as::<_, models::VulnerabilityTracking>(
        "SELECT * FROM vulnerability_tracking WHERE id = ?1",
    )
    .bind(vuln_id)
    .fetch_one(pool)
    .await?;

    Ok(updated)
}

/// Bulk assign vulnerabilities to a user
pub async fn bulk_assign_vulnerabilities(
    pool: &SqlitePool,
    vulnerability_ids: &[String],
    assignee_id: &str,
    user_id: &str,
) -> Result<usize> {
    if vulnerability_ids.is_empty() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for vuln_id in vulnerability_ids {
        // Update assignee
        let result = sqlx::query(
            "UPDATE vulnerability_tracking SET updated_at = ?1, assignee_id = ?2 WHERE id = ?3",
        )
        .bind(now)
        .bind(assignee_id)
        .bind(vuln_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() > 0 {
            // Create timeline event
            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO remediation_timeline (id, vulnerability_tracking_id, user_id, event_type, old_value, new_value, comment, created_at)
                VALUES (?1, ?2, ?3, 'assignment', NULL, ?4, 'Bulk assigned', ?5)
                "#,
            )
            .bind(&event_id)
            .bind(vuln_id)
            .bind(user_id)
            .bind(assignee_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;

            updated_count += 1;
        }
    }

    tx.commit().await?;
    Ok(updated_count)
}

/// Validate workflow state transitions
pub fn validate_status_transition(current_status: &str, new_status: &str) -> Result<()> {
    // State machine: open -> in_progress -> pending_verification -> resolved
    // Can also go to false_positive or accepted_risk from any state
    let valid_transitions = match current_status {
        "open" => vec!["in_progress", "false_positive", "accepted_risk", "resolved"],
        "in_progress" => vec!["open", "pending_verification", "resolved", "false_positive", "accepted_risk"],
        "pending_verification" => vec!["in_progress", "resolved", "false_positive"],
        "resolved" => vec!["in_progress", "open"], // Allow reopening
        "false_positive" => vec!["open", "in_progress"],
        "accepted_risk" => vec!["open", "in_progress"],
        _ => vec![],
    };

    if !valid_transitions.contains(&new_status) {
        return Err(anyhow::anyhow!(
            "Invalid status transition from '{}' to '{}'",
            current_status,
            new_status
        ));
    }

    Ok(())
}

/// Get vulnerability statistics for a scan
pub async fn get_vulnerability_statistics(
    pool: &SqlitePool,
    scan_id: Option<&str>,
) -> Result<models::VulnerabilityStats> {
    let query = if let Some(sid) = scan_id {
        format!(
            r#"
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
                SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive,
                SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END) as accepted_risk,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
            FROM vulnerability_tracking
            WHERE scan_id = '{}'
            "#,
            sid
        )
    } else {
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved,
            SUM(CASE WHEN status = 'false_positive' THEN 1 ELSE 0 END) as false_positive,
            SUM(CASE WHEN status = 'accepted_risk' THEN 1 ELSE 0 END) as accepted_risk,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM vulnerability_tracking
        "#
        .to_string()
    };

    let row = sqlx::query(&query).fetch_one(pool).await?;

    let stats = models::VulnerabilityStats {
        total: row.try_get("total").unwrap_or(0),
        open: row.try_get("open").unwrap_or(0),
        in_progress: row.try_get("in_progress").unwrap_or(0),
        resolved: row.try_get("resolved").unwrap_or(0),
        false_positive: row.try_get("false_positive").unwrap_or(0),
        accepted_risk: row.try_get("accepted_risk").unwrap_or(0),
        critical: row.try_get("critical").unwrap_or(0),
        high: row.try_get("high").unwrap_or(0),
        medium: row.try_get("medium").unwrap_or(0),
        low: row.try_get("low").unwrap_or(0),
    };

    Ok(stats)
}

// ============================================================================
// Refresh Token Management Functions (NIST 800-63B)
// ============================================================================

/// Hash a token with SHA-256 for secure storage
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Store a refresh token in the database (hashes token with SHA-256 before storing)
pub async fn store_refresh_token(
    pool: &SqlitePool,
    user_id: &str,
    token: &str,
    expires_at: DateTime<Utc>,
) -> Result<models::RefreshToken> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Hash the token with SHA-256 before storing
    let token_hash = hash_token(token);

    let stored_token = sqlx::query_as::<_, models::RefreshToken>(
        r#"
        INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(stored_token)
}

/// Get a refresh token by its hash (hashes the provided token before lookup)
pub async fn get_refresh_token(
    pool: &SqlitePool,
    token: &str,
) -> Result<Option<models::RefreshToken>> {
    // Hash the token with SHA-256 before comparing
    let token_hash = hash_token(token);

    let token = sqlx::query_as::<_, models::RefreshToken>(
        "SELECT * FROM refresh_tokens WHERE token_hash = ?1 AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(token)
}

/// Revoke a specific refresh token (hashes the provided token before revoking)
pub async fn revoke_refresh_token(pool: &SqlitePool, token: &str) -> Result<()> {
    let now = Utc::now();

    // Hash the token with SHA-256 before revoking
    let token_hash = hash_token(token);

    sqlx::query("UPDATE refresh_tokens SET revoked_at = ?1 WHERE token_hash = ?2")
        .bind(now)
        .bind(&token_hash)
        .execute(pool)
        .await?;

    Ok(())
}

/// Revoke all refresh tokens for a user (useful for logout all sessions)
pub async fn revoke_all_user_refresh_tokens(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE refresh_tokens SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Clean up expired refresh tokens (can be called periodically)
pub async fn cleanup_expired_refresh_tokens(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now();

    sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < ?1")
        .bind(now)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Account Lockout and Login Attempt Tracking (NIST 800-53 AC-7, CIS Controls 16.11)
// ============================================================================

/// Record a login attempt (both successful and failed) for audit and security purposes
pub async fn record_login_attempt(
    pool: &SqlitePool,
    username: &str,
    success: bool,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO login_attempts (username, attempt_time, success, ip_address, user_agent)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(username)
    .bind(now)
    .bind(success)
    .bind(ip_address)
    .bind(user_agent)
    .execute(pool)
    .await?;

    Ok(())
}

/// Check if an account is currently locked
/// Returns (is_locked, locked_until, attempt_count)
pub async fn check_account_locked(
    pool: &SqlitePool,
    username: &str,
) -> Result<(bool, Option<DateTime<Utc>>, i32)> {
    let now = Utc::now();

    // First, try to get lockout record
    let lockout: Option<(DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT locked_until, attempt_count FROM account_lockouts WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    if let Some((locked_until, attempt_count)) = lockout {
        // Check if lockout has expired
        if locked_until > now {
            // Account is still locked
            return Ok((true, Some(locked_until), attempt_count));
        } else {
            // Lockout has expired, clean up the record
            sqlx::query("DELETE FROM account_lockouts WHERE username = ?1")
                .bind(username)
                .execute(pool)
                .await?;
            return Ok((false, None, 0));
        }
    }

    Ok((false, None, 0))
}

/// Increment failed login attempts and lock account if threshold is reached
/// Returns (is_now_locked, locked_until, attempt_count)
pub async fn increment_failed_attempts(
    pool: &SqlitePool,
    username: &str,
) -> Result<(bool, Option<DateTime<Utc>>, i32)> {
    const MAX_ATTEMPTS: i32 = 5;
    const LOCKOUT_DURATION_MINUTES: i64 = 15;

    let now = Utc::now();

    // Get current lockout status
    let existing: Option<(i32, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT attempt_count, first_failed_attempt, last_failed_attempt FROM account_lockouts WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    if let Some((current_count, first_attempt, _last_attempt)) = existing {
        let new_count = current_count + 1;

        if new_count >= MAX_ATTEMPTS {
            // Lock the account
            let locked_until = now + chrono::Duration::minutes(LOCKOUT_DURATION_MINUTES);

            sqlx::query(
                r#"
                UPDATE account_lockouts
                SET attempt_count = ?1, last_failed_attempt = ?2, locked_until = ?3,
                    lockout_reason = ?4
                WHERE username = ?5
                "#,
            )
            .bind(new_count)
            .bind(now)
            .bind(locked_until)
            .bind(format!("Account locked due to {} consecutive failed login attempts", new_count))
            .bind(username)
            .execute(pool)
            .await?;

            return Ok((true, Some(locked_until), new_count));
        } else {
            // Increment attempt count but don't lock yet
            sqlx::query(
                "UPDATE account_lockouts SET attempt_count = ?1, last_failed_attempt = ?2 WHERE username = ?3",
            )
            .bind(new_count)
            .bind(now)
            .bind(username)
            .execute(pool)
            .await?;

            return Ok((false, None, new_count));
        }
    } else {
        // First failed attempt, create new record
        let locked_until = now + chrono::Duration::minutes(LOCKOUT_DURATION_MINUTES);

        sqlx::query(
            r#"
            INSERT INTO account_lockouts (username, locked_until, attempt_count, first_failed_attempt, last_failed_attempt, lockout_reason)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(username)
        .bind(locked_until)
        .bind(1)
        .bind(now)
        .bind(now)
        .bind("Initial failed login attempt")
        .execute(pool)
        .await?;

        return Ok((false, None, 1));
    }
}

/// Reset failed login attempts after successful login
pub async fn reset_failed_attempts(pool: &SqlitePool, username: &str) -> Result<()> {
    sqlx::query("DELETE FROM account_lockouts WHERE username = ?1")
        .bind(username)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get recent login attempts for a username (for audit purposes)
pub async fn get_recent_login_attempts(
    pool: &SqlitePool,
    username: &str,
    limit: i64,
) -> Result<Vec<models::LoginAttempt>> {
    let attempts = sqlx::query_as::<_, models::LoginAttempt>(
        "SELECT * FROM login_attempts WHERE username = ?1 ORDER BY attempt_time DESC LIMIT ?2",
    )
    .bind(username)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(attempts)
}

// ============================================================================
// GDPR Compliance Functions
// ============================================================================

/// Accept terms and conditions for an existing user
pub async fn accept_terms(pool: &SqlitePool, user_id: &str) -> Result<models::User> {
    let now = Utc::now();
    let terms_version = "1.0"; // Current terms version

    let user = sqlx::query_as::<_, models::User>(
        "UPDATE users SET accepted_terms_at = ?1, terms_version = ?2 WHERE id = ?3 RETURNING *",
    )
    .bind(now)
    .bind(terms_version)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Export all user data for GDPR compliance
pub async fn export_user_data(pool: &SqlitePool, user_id: &str) -> Result<models::UserDataExport> {
    // Get user info
    let user = get_user_by_id(pool, user_id).await?
        .ok_or_else(|| anyhow::anyhow!("User not found"))?;

    // Get user's scans
    let scans = get_user_scans(pool, user_id).await?;

    // Get user's reports
    let reports = get_user_reports(pool, user_id).await?;

    // Get user's templates
    let templates = get_user_templates(pool, user_id).await?;

    // Get user's target groups
    let target_groups = get_user_target_groups(pool, user_id).await?;

    // Get user's scheduled scans
    let scheduled_scans = get_user_scheduled_scans(pool, user_id).await?;

    // Get user's notification settings
    let notification_settings = get_notification_settings(pool, user_id).await.ok();

    Ok(models::UserDataExport {
        user: models::UserExportData {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: user.created_at,
            is_active: user.is_active,
            accepted_terms_at: user.accepted_terms_at,
            terms_version: user.terms_version,
        },
        scans,
        reports,
        templates,
        target_groups,
        scheduled_scans,
        notification_settings,
    })
}

/// Delete user account and all associated data (GDPR right to be forgotten)
pub async fn delete_user_account(pool: &SqlitePool, user_id: &str) -> Result<()> {
    // Delete user's reports (files should be cleaned up separately)
    sqlx::query("DELETE FROM reports WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's scans
    sqlx::query("DELETE FROM scan_results WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's templates
    sqlx::query("DELETE FROM scan_templates WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's target groups
    sqlx::query("DELETE FROM target_groups WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's scheduled scans
    sqlx::query("DELETE FROM scheduled_scans WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's notification settings
    sqlx::query("DELETE FROM notification_settings WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user's refresh tokens
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Delete user roles
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    // Finally, delete the user
    sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// MFA (Two-Factor Authentication) Database Functions
// ============================================================================

/// Get the encryption key for TOTP secrets from environment variable
fn get_totp_encryption_key() -> Result<[u8; 32]> {
    let key_str = std::env::var("TOTP_ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!("TOTP_ENCRYPTION_KEY environment variable not set. Generate one with: openssl rand -hex 32"))?;

    // Decode hex key to bytes
    let key_bytes = hex::decode(&key_str)
        .map_err(|_| anyhow::anyhow!("TOTP_ENCRYPTION_KEY must be a valid hex string (64 characters)"))?;

    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!("TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt TOTP secret with AES-256-GCM
fn encrypt_totp_secret(secret: &str) -> Result<String> {
    let key_bytes = get_totp_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Generate random nonce (12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the secret
    let ciphertext = cipher.encrypt(nonce, secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt TOTP secret with AES-256-GCM
fn decrypt_totp_secret(encrypted: &str) -> Result<String> {
    let key_bytes = get_totp_encryption_key()?;
    let cipher = Aes256Gcm::new(key_bytes.as_ref().into());

    // Decode from base64
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| anyhow::anyhow!("Failed to decode encrypted TOTP secret: {}", e))?;

    if combined.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted TOTP secret: too short"));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    let secret = String::from_utf8(plaintext)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted TOTP secret: {}", e))?;

    Ok(secret)
}

/// Store TOTP secret for a user (encrypts with AES-256-GCM before storing)
pub async fn store_totp_secret(pool: &SqlitePool, user_id: &str, secret: &str) -> Result<()> {
    // Encrypt the secret with AES-256-GCM
    let encrypted_secret = encrypt_totp_secret(secret)?;

    sqlx::query("UPDATE users SET totp_secret = ?1 WHERE id = ?2")
        .bind(&encrypted_secret)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get TOTP secret for a user (decrypts after retrieving)
pub async fn get_totp_secret(pool: &SqlitePool, user_id: &str) -> Result<Option<String>> {
    let result: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT totp_secret FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some((Some(encrypted_secret),)) = result {
        // Decrypt the secret with AES-256-GCM
        let secret = decrypt_totp_secret(&encrypted_secret)?;
        Ok(Some(secret))
    } else {
        Ok(None)
    }
}

/// Enable MFA for a user after successful verification
pub async fn enable_mfa(pool: &SqlitePool, user_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE users SET totp_enabled = 1, totp_verified_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Disable MFA for a user
pub async fn disable_mfa(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_verified_at = NULL, recovery_codes = NULL WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Check if MFA is enabled for a user
pub async fn is_mfa_enabled(pool: &SqlitePool, user_id: &str) -> Result<bool> {
    let result: Option<(bool,)> = sqlx::query_as(
        "SELECT totp_enabled FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|(enabled,)| enabled).unwrap_or(false))
}

/// Store hashed recovery codes for a user (JSON array of bcrypt hashes)
pub async fn store_recovery_codes(pool: &SqlitePool, user_id: &str, codes: &[String]) -> Result<()> {
    // Hash each recovery code with bcrypt
    let mut hashed_codes = Vec::new();
    for code in codes {
        let hash = bcrypt::hash(code, *BCRYPT_COST)?;
        hashed_codes.push(hash);
    }

    let codes_json = serde_json::to_string(&hashed_codes)?;

    sqlx::query("UPDATE users SET recovery_codes = ?1 WHERE id = ?2")
        .bind(&codes_json)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Verify and consume a recovery code (removes it after successful verification)
pub async fn verify_and_consume_recovery_code(
    pool: &SqlitePool,
    user_id: &str,
    code: &str,
) -> Result<bool> {
    // Get current recovery codes
    let result: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT recovery_codes FROM users WHERE id = ?1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    if let Some((Some(codes_json),)) = result {
        let mut hashed_codes: Vec<String> = serde_json::from_str(&codes_json)?;

        // Check each hashed code
        for (i, hashed_code) in hashed_codes.iter().enumerate() {
            if bcrypt::verify(code, hashed_code).unwrap_or(false) {
                // Code is valid - remove it from the list
                hashed_codes.remove(i);

                // Update database with remaining codes
                let updated_json = serde_json::to_string(&hashed_codes)?;
                sqlx::query("UPDATE users SET recovery_codes = ?1 WHERE id = ?2")
                    .bind(&updated_json)
                    .bind(user_id)
                    .execute(pool)
                    .await?;

                return Ok(true);
            }
        }
    }

    Ok(false)
}

// ============================================================================
// Password History Functions (NIST 800-63B - prevent password reuse)
// ============================================================================

/// Check if a password was used recently (checks last 5 passwords)
pub async fn check_password_history(
    pool: &SqlitePool,
    user_id: &str,
    new_password: &str,
) -> Result<bool> {
    // Get last 5 password hashes for this user
    let history: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT password_hash FROM password_history
        WHERE user_id = ?1
        ORDER BY created_at DESC
        LIMIT 5
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    // Check if new password matches any recent password
    for (old_hash,) in history {
        if bcrypt::verify(new_password, &old_hash).unwrap_or(false) {
            return Ok(true); // Password was used recently
        }
    }

    Ok(false) // Password is not in recent history
}

/// Add a password hash to history and maintain limit of 5
pub async fn add_password_to_history(
    pool: &SqlitePool,
    user_id: &str,
    password_hash: &str,
) -> Result<()> {
    let now = Utc::now();

    // Insert new password hash
    sqlx::query(
        r#"
        INSERT INTO password_history (user_id, password_hash, created_at)
        VALUES (?1, ?2, ?3)
        "#,
    )
    .bind(user_id)
    .bind(password_hash)
    .bind(now)
    .execute(pool)
    .await?;

    // Get count of password history entries for this user
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM password_history WHERE user_id = ?1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // If more than 5, remove oldest entries
    if count.0 > 5 {
        let to_remove = count.0 - 5;
        sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE id IN (
                SELECT id FROM password_history
                WHERE user_id = ?1
                ORDER BY created_at ASC
                LIMIT ?2
            )
            "#,
        )
        .bind(user_id)
        .bind(to_remove)
        .execute(pool)
        .await?;
    }

    Ok(())
}

// ============================================================================
// Re-export Analytics Functions
// ============================================================================

pub use analytics::{
    get_analytics_summary,
    get_hosts_over_time,
    get_vulnerabilities_over_time,
    get_top_services,
    get_scan_frequency,
};

// ============================================================================
// API Keys Management Functions
// ============================================================================

/// Generate a new API key with format hf_<random_32_chars>
fn generate_api_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let key: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    format!("hf_{}", key)
}

/// Create a new API key for a user
pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateApiKeyRequest,
) -> Result<models::CreateApiKeyResponse> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Generate API key
    let key = generate_api_key();
    let prefix = key.chars().take(8).collect::<String>();
    let key_hash = bcrypt::hash(&key, *BCRYPT_COST)?;

    // Serialize permissions to JSON
    let permissions_json = request.permissions
        .as_ref()
        .map(|p| serde_json::to_string(p).ok())
        .flatten();

    let api_key = sqlx::query_as::<_, models::ApiKey>(
        r#"
        INSERT INTO api_keys (id, user_id, name, key_hash, prefix, permissions, created_at, expires_at, is_active)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.name)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(&permissions_json)
    .bind(now)
    .bind(&request.expires_at)
    .bind(true)
    .fetch_one(pool)
    .await?;

    Ok(models::CreateApiKeyResponse {
        id: api_key.id,
        name: api_key.name,
        key, // Return full key only once
        prefix: api_key.prefix,
        permissions: request.permissions.clone(),
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
    })
}

/// Get all API keys for a user (without key_hash)
pub async fn get_user_api_keys(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::ApiKey>> {
    let keys = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(keys)
}

/// Get API key by ID (for a specific user)
pub async fn get_api_key_by_id(
    pool: &SqlitePool,
    key_id: &str,
    user_id: &str,
) -> Result<Option<models::ApiKey>> {
    let key = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2",
    )
    .bind(key_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(key)
}

/// Verify an API key and return the user_id if valid
pub async fn verify_api_key(pool: &SqlitePool, api_key: &str) -> Result<Option<String>> {
    // Get the prefix (first 8 chars)
    if api_key.len() < 8 {
        return Ok(None);
    }
    let prefix = api_key.chars().take(8).collect::<String>();

    // Find keys with matching prefix
    let keys = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE prefix = ?1 AND is_active = 1",
    )
    .bind(&prefix)
    .fetch_all(pool)
    .await?;

    // Check each key with bcrypt
    for key in keys {
        // Check if expired
        if let Some(expires_at) = key.expires_at {
            if expires_at < Utc::now() {
                continue;
            }
        }

        // Verify hash
        if bcrypt::verify(api_key, &key.key_hash).unwrap_or(false) {
            // Update last_used_at
            let _ = update_api_key_last_used(pool, &key.id).await;
            return Ok(Some(key.user_id));
        }
    }

    Ok(None)
}

/// Update last_used_at timestamp for an API key
async fn update_api_key_last_used(pool: &SqlitePool, key_id: &str) -> Result<()> {
    let now = Utc::now();
    sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2")
        .bind(now)
        .bind(key_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update an API key (name or permissions)
pub async fn update_api_key(
    pool: &SqlitePool,
    key_id: &str,
    user_id: &str,
    request: &models::UpdateApiKeyRequest,
) -> Result<models::ApiKey> {
    let now = Utc::now();

    if let Some(name) = &request.name {
        sqlx::query("UPDATE api_keys SET name = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(name)
            .bind(key_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    if let Some(permissions) = &request.permissions {
        let permissions_json = serde_json::to_string(permissions)?;
        sqlx::query("UPDATE api_keys SET permissions = ?1 WHERE id = ?2 AND user_id = ?3")
            .bind(&permissions_json)
            .bind(key_id)
            .bind(user_id)
            .execute(pool)
            .await?;
    }

    let key = sqlx::query_as::<_, models::ApiKey>(
        "SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2",
    )
    .bind(key_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(key)
}

/// Delete (revoke) an API key
pub async fn delete_api_key(pool: &SqlitePool, key_id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2")
        .bind(key_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}


// ============================================================================
// SIEM Settings Functions
// ============================================================================

/// Get SIEM settings for a user
pub async fn get_siem_settings(pool: &SqlitePool, user_id: &str) -> Result<Vec<models::SiemSettings>> {
    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE user_id = ?1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

/// Get SIEM settings by ID
pub async fn get_siem_settings_by_id(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
) -> Result<Option<models::SiemSettings>> {
    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(settings)
}

/// Create SIEM settings
pub async fn create_siem_settings(
    pool: &SqlitePool,
    user_id: &str,
    request: &models::CreateSiemSettingsRequest,
) -> Result<models::SiemSettings> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let settings = sqlx::query_as::<_, models::SiemSettings>(
        r#"
        INSERT INTO siem_settings (
            id, user_id, siem_type, endpoint_url, api_key, protocol,
            enabled, export_on_scan_complete, export_on_critical_vuln,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&request.siem_type)
    .bind(&request.endpoint_url)
    .bind(&request.api_key)
    .bind(&request.protocol)
    .bind(request.enabled)
    .bind(request.export_on_scan_complete)
    .bind(request.export_on_critical_vuln)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Update SIEM settings
pub async fn update_siem_settings(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
    request: &models::UpdateSiemSettingsRequest,
) -> Result<models::SiemSettings> {
    let now = Utc::now();

    if let Some(endpoint_url) = &request.endpoint_url {
        sqlx::query(
            "UPDATE siem_settings SET endpoint_url = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(endpoint_url)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(api_key) = &request.api_key {
        sqlx::query(
            "UPDATE siem_settings SET api_key = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(api_key)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(protocol) = &request.protocol {
        sqlx::query(
            "UPDATE siem_settings SET protocol = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(protocol)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(enabled) = request.enabled {
        sqlx::query(
            "UPDATE siem_settings SET enabled = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(enabled)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(export_on_scan_complete) = request.export_on_scan_complete {
        sqlx::query(
            "UPDATE siem_settings SET export_on_scan_complete = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(export_on_scan_complete)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    if let Some(export_on_critical_vuln) = request.export_on_critical_vuln {
        sqlx::query(
            "UPDATE siem_settings SET export_on_critical_vuln = ?1, updated_at = ?2 WHERE id = ?3 AND user_id = ?4"
        )
        .bind(export_on_critical_vuln)
        .bind(now)
        .bind(settings_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    }

    let settings = sqlx::query_as::<_, models::SiemSettings>(
        "SELECT * FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(settings)
}

/// Delete SIEM settings
pub async fn delete_siem_settings(
    pool: &SqlitePool,
    settings_id: &str,
    user_id: &str,
) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM siem_settings WHERE id = ?1 AND user_id = ?2"
    )
    .bind(settings_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

