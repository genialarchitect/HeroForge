#![allow(dead_code)]

pub mod models;
pub mod migrations;

use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;

pub async fn init_database(database_url: &str) -> Result<SqlitePool> {
    use sqlx::sqlite::SqlitePoolOptions;

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

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
    let id = uuid::Uuid::new_v4().to_string();
    let password_hash = bcrypt::hash(&user.password, bcrypt::DEFAULT_COST)?;
    let now = chrono::Utc::now();

    let user = sqlx::query_as::<_, models::User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, created_at, is_active)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(&password_hash)
    .bind(now)
    .bind(true)
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
