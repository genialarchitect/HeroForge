//! Database operations for Windows credentialed audit scanning
//!
//! This module provides CRUD operations for Windows audit scans, credentials,
//! STIG profiles, and scan results.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Windows audit scan database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsAuditScan {
    pub id: String,
    pub scan_id: String,
    pub target_host: String,
    pub target_ip: Option<String>,
    pub credential_id: Option<String>,
    pub stig_profile_id: Option<String>,
    pub status: String, // "pending", "connecting", "scanning", "completed", "failed"
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    pub computer_name: Option<String>,
    pub domain: Option<String>,
    pub total_checks: i32,
    pub passed_checks: i32,
    pub failed_checks: i32,
    pub error_checks: i32,
    pub not_applicable: i32,
    pub cat1_findings: i32,
    pub cat2_findings: i32,
    pub cat3_findings: i32,
    pub compliance_score: Option<f64>,
    pub error_message: Option<String>,
    pub executed_by: String,
    pub created_at: String,
}

/// Windows audit credential database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsAuditCredential {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub credential_type: String, // "local", "domain", "certificate"
    pub username: String,
    pub password_encrypted: String,
    pub domain: Option<String>,
    pub use_ssl: bool,
    pub port: i32,
    pub auth_method: String, // "ntlm", "kerberos", "negotiate"
    pub is_active: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

/// Windows STIG profile database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsStigProfile {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub os_type: String, // "server_2022", "server_2019", "server_2016", "win11", "win10"
    pub stig_version: String,
    pub release_date: String,
    pub enabled_checks: String, // JSON array of check IDs
    pub disabled_checks: String, // JSON array of check IDs
    pub cat1_enabled: bool,
    pub cat2_enabled: bool,
    pub cat3_enabled: bool,
    pub is_default: bool,
    pub is_system: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Windows audit check result database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsAuditResult {
    pub id: String,
    pub scan_id: String,
    pub check_id: String,
    pub stig_id: Option<String>,
    pub cci_id: Option<String>,
    pub check_name: String,
    pub category: String, // "CAT1", "CAT2", "CAT3"
    pub result: String, // "pass", "fail", "error", "not_applicable", "not_checked"
    pub expected_value: Option<String>,
    pub actual_value: Option<String>,
    pub finding_details: Option<String>,
    pub fix_text: Option<String>,
    pub severity: String,
    pub check_type: String, // "registry", "policy", "service", "file", "audit", "firewall"
    pub evaluated_at: String,
}

/// Windows system snapshot database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsSystemSnapshot {
    pub id: String,
    pub scan_id: String,
    pub snapshot_type: String, // "registry", "services", "users", "groups", "firewall", "audit_policy", "gpo"
    pub snapshot_data: String, // JSON
    pub collected_at: String,
}

/// Windows audit schedule record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowsAuditSchedule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub target_hosts: String, // JSON array
    pub credential_id: String,
    pub stig_profile_id: Option<String>,
    pub cron_expression: String,
    pub timezone: String,
    pub is_active: bool,
    pub next_run_at: Option<String>,
    pub last_run_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize Windows audit database tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Windows audit scans
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_audit_scans (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            target_host TEXT NOT NULL,
            target_ip TEXT,
            credential_id TEXT,
            stig_profile_id TEXT,
            status TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            os_version TEXT,
            os_build TEXT,
            computer_name TEXT,
            domain TEXT,
            total_checks INTEGER NOT NULL DEFAULT 0,
            passed_checks INTEGER NOT NULL DEFAULT 0,
            failed_checks INTEGER NOT NULL DEFAULT 0,
            error_checks INTEGER NOT NULL DEFAULT 0,
            not_applicable INTEGER NOT NULL DEFAULT 0,
            cat1_findings INTEGER NOT NULL DEFAULT 0,
            cat2_findings INTEGER NOT NULL DEFAULT 0,
            cat3_findings INTEGER NOT NULL DEFAULT 0,
            compliance_score REAL,
            error_message TEXT,
            executed_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Windows audit credentials (encrypted)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_audit_credentials (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            credential_type TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            domain TEXT,
            use_ssl INTEGER NOT NULL DEFAULT 1,
            port INTEGER NOT NULL DEFAULT 5985,
            auth_method TEXT NOT NULL DEFAULT 'negotiate',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Windows STIG profiles
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_stig_profiles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            os_type TEXT NOT NULL,
            stig_version TEXT NOT NULL,
            release_date TEXT NOT NULL,
            enabled_checks TEXT NOT NULL,
            disabled_checks TEXT NOT NULL DEFAULT '[]',
            cat1_enabled INTEGER NOT NULL DEFAULT 1,
            cat2_enabled INTEGER NOT NULL DEFAULT 1,
            cat3_enabled INTEGER NOT NULL DEFAULT 1,
            is_default INTEGER NOT NULL DEFAULT 0,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Windows audit results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_audit_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            check_id TEXT NOT NULL,
            stig_id TEXT,
            cci_id TEXT,
            check_name TEXT NOT NULL,
            category TEXT NOT NULL,
            result TEXT NOT NULL,
            expected_value TEXT,
            actual_value TEXT,
            finding_details TEXT,
            fix_text TEXT,
            severity TEXT NOT NULL,
            check_type TEXT NOT NULL,
            evaluated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES windows_audit_scans(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Windows system snapshots
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_system_snapshots (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            snapshot_type TEXT NOT NULL,
            snapshot_data TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES windows_audit_scans(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Windows audit schedules
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS windows_audit_schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            target_hosts TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            stig_profile_id TEXT,
            cron_expression TEXT NOT NULL,
            timezone TEXT NOT NULL DEFAULT 'UTC',
            is_active INTEGER NOT NULL DEFAULT 1,
            next_run_at TEXT,
            last_run_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (credential_id) REFERENCES windows_audit_credentials(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_win_audit_scans_scan ON windows_audit_scans(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_win_audit_scans_host ON windows_audit_scans(target_host)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_win_audit_results_scan ON windows_audit_results(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_win_audit_results_cat ON windows_audit_results(category)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_win_snapshots_scan ON windows_system_snapshots(scan_id)")
        .execute(pool)
        .await?;

    // Insert default STIG profiles
    insert_default_profiles(pool).await?;

    Ok(())
}

/// Insert default STIG profiles
async fn insert_default_profiles(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    // Check if default profiles already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM windows_stig_profiles WHERE is_system = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    if count.0 > 0 {
        return Ok(());
    }

    // Windows Server 2022 STIG
    sqlx::query(
        r#"
        INSERT INTO windows_stig_profiles (
            id, name, description, os_type, stig_version, release_date,
            enabled_checks, disabled_checks, cat1_enabled, cat2_enabled, cat3_enabled,
            is_default, is_system, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("Windows Server 2022 STIG")
    .bind("DISA Windows Server 2022 Security Technical Implementation Guide")
    .bind("server_2022")
    .bind("V1R1")
    .bind("2024-01-01")
    .bind("[]") // All checks enabled by default
    .bind("[]")
    .bind(true)
    .bind(true)
    .bind(true)
    .bind(true) // Default profile
    .bind(true) // System profile
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Windows Server 2019 STIG
    sqlx::query(
        r#"
        INSERT INTO windows_stig_profiles (
            id, name, description, os_type, stig_version, release_date,
            enabled_checks, disabled_checks, cat1_enabled, cat2_enabled, cat3_enabled,
            is_default, is_system, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("Windows Server 2019 STIG")
    .bind("DISA Windows Server 2019 Security Technical Implementation Guide")
    .bind("server_2019")
    .bind("V3R1")
    .bind("2024-01-01")
    .bind("[]")
    .bind("[]")
    .bind(true)
    .bind(true)
    .bind(true)
    .bind(false)
    .bind(true)
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // Windows 10 STIG
    sqlx::query(
        r#"
        INSERT INTO windows_stig_profiles (
            id, name, description, os_type, stig_version, release_date,
            enabled_checks, disabled_checks, cat1_enabled, cat2_enabled, cat3_enabled,
            is_default, is_system, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("Windows 10 STIG")
    .bind("DISA Windows 10 Security Technical Implementation Guide")
    .bind("win10")
    .bind("V2R8")
    .bind("2024-01-01")
    .bind("[]")
    .bind("[]")
    .bind(true)
    .bind(true)
    .bind(true)
    .bind(false)
    .bind(true)
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Scan Operations
// ============================================================================

/// Create a new Windows audit scan
pub async fn create_scan(pool: &SqlitePool, scan: &WindowsAuditScan) -> Result<String> {
    let id = if scan.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        scan.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO windows_audit_scans (
            id, scan_id, target_host, target_ip, credential_id, stig_profile_id,
            status, started_at, completed_at, os_version, os_build, computer_name,
            domain, total_checks, passed_checks, failed_checks, error_checks,
            not_applicable, cat1_findings, cat2_findings, cat3_findings,
            compliance_score, error_message, executed_by, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25)
        "#,
    )
    .bind(&id)
    .bind(&scan.scan_id)
    .bind(&scan.target_host)
    .bind(&scan.target_ip)
    .bind(&scan.credential_id)
    .bind(&scan.stig_profile_id)
    .bind(&scan.status)
    .bind(&scan.started_at)
    .bind(&scan.completed_at)
    .bind(&scan.os_version)
    .bind(&scan.os_build)
    .bind(&scan.computer_name)
    .bind(&scan.domain)
    .bind(scan.total_checks)
    .bind(scan.passed_checks)
    .bind(scan.failed_checks)
    .bind(scan.error_checks)
    .bind(scan.not_applicable)
    .bind(scan.cat1_findings)
    .bind(scan.cat2_findings)
    .bind(scan.cat3_findings)
    .bind(scan.compliance_score)
    .bind(&scan.error_message)
    .bind(&scan.executed_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get scan by ID
pub async fn get_scan(pool: &SqlitePool, id: &str) -> Result<Option<WindowsAuditScan>> {
    let scan = sqlx::query_as::<_, WindowsAuditScan>(
        "SELECT * FROM windows_audit_scans WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(scan)
}

/// Get scans for a parent scan
pub async fn get_scans_for_parent(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<WindowsAuditScan>> {
    let scans = sqlx::query_as::<_, WindowsAuditScan>(
        "SELECT * FROM windows_audit_scans WHERE scan_id = ?1 ORDER BY created_at DESC",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(scans)
}

/// Update scan status and results
pub async fn update_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    os_info: Option<(&str, &str, &str, &str)>,
    results: Option<(i32, i32, i32, i32, i32, i32, i32, i32, f64)>,
    error_message: Option<&str>,
) -> Result<()> {
    let completed_at = if status == "completed" || status == "failed" {
        Some(Utc::now().to_rfc3339())
    } else {
        None
    };

    if let Some((os_version, os_build, computer_name, domain)) = os_info {
        sqlx::query(
            "UPDATE windows_audit_scans SET os_version = ?1, os_build = ?2, computer_name = ?3, domain = ?4 WHERE id = ?5",
        )
        .bind(os_version)
        .bind(os_build)
        .bind(computer_name)
        .bind(domain)
        .bind(id)
        .execute(pool)
        .await?;
    }

    if let Some((total, passed, failed, errors, na, cat1, cat2, cat3, score)) = results {
        sqlx::query(
            r#"
            UPDATE windows_audit_scans
            SET status = ?1, completed_at = ?2, total_checks = ?3, passed_checks = ?4,
                failed_checks = ?5, error_checks = ?6, not_applicable = ?7,
                cat1_findings = ?8, cat2_findings = ?9, cat3_findings = ?10,
                compliance_score = ?11, error_message = ?12
            WHERE id = ?13
            "#,
        )
        .bind(status)
        .bind(&completed_at)
        .bind(total)
        .bind(passed)
        .bind(failed)
        .bind(errors)
        .bind(na)
        .bind(cat1)
        .bind(cat2)
        .bind(cat3)
        .bind(score)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE windows_audit_scans SET status = ?1, completed_at = ?2, error_message = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(&completed_at)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// List recent scans
pub async fn list_recent_scans(
    pool: &SqlitePool,
    limit: i32,
    offset: i32,
    status: Option<&str>,
) -> Result<Vec<WindowsAuditScan>> {
    let mut query = String::from("SELECT * FROM windows_audit_scans WHERE 1=1");

    if let Some(s) = status {
        query.push_str(&format!(" AND status = '{}'", s));
    }

    query.push_str(&format!(" ORDER BY created_at DESC LIMIT {} OFFSET {}", limit, offset));

    let scans = sqlx::query_as::<_, WindowsAuditScan>(&query)
        .fetch_all(pool)
        .await?;

    Ok(scans)
}

// ============================================================================
// Credential Operations
// ============================================================================

/// Create a new credential
pub async fn create_credential(
    pool: &SqlitePool,
    credential: &WindowsAuditCredential,
) -> Result<String> {
    let id = if credential.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        credential.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO windows_audit_credentials (
            id, name, description, credential_type, username, password_encrypted,
            domain, use_ssl, port, auth_method, is_active, created_by,
            created_at, updated_at, last_used_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&credential.name)
    .bind(&credential.description)
    .bind(&credential.credential_type)
    .bind(&credential.username)
    .bind(&credential.password_encrypted)
    .bind(&credential.domain)
    .bind(credential.use_ssl)
    .bind(credential.port)
    .bind(&credential.auth_method)
    .bind(credential.is_active)
    .bind(&credential.created_by)
    .bind(&now)
    .bind(&now)
    .bind(&credential.last_used_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get credential by ID
pub async fn get_credential(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<WindowsAuditCredential>> {
    let credential = sqlx::query_as::<_, WindowsAuditCredential>(
        "SELECT * FROM windows_audit_credentials WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(credential)
}

/// List credentials for user
pub async fn list_credentials(pool: &SqlitePool, created_by: &str) -> Result<Vec<WindowsAuditCredential>> {
    let credentials = sqlx::query_as::<_, WindowsAuditCredential>(
        "SELECT * FROM windows_audit_credentials WHERE created_by = ?1 AND is_active = 1 ORDER BY name",
    )
    .bind(created_by)
    .fetch_all(pool)
    .await?;

    Ok(credentials)
}

/// Update credential
pub async fn update_credential(pool: &SqlitePool, credential: &WindowsAuditCredential) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE windows_audit_credentials
        SET name = ?1, description = ?2, credential_type = ?3, username = ?4,
            password_encrypted = ?5, domain = ?6, use_ssl = ?7, port = ?8,
            auth_method = ?9, is_active = ?10, updated_at = ?11
        WHERE id = ?12
        "#,
    )
    .bind(&credential.name)
    .bind(&credential.description)
    .bind(&credential.credential_type)
    .bind(&credential.username)
    .bind(&credential.password_encrypted)
    .bind(&credential.domain)
    .bind(credential.use_ssl)
    .bind(credential.port)
    .bind(&credential.auth_method)
    .bind(credential.is_active)
    .bind(&now)
    .bind(&credential.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update credential last used timestamp
pub async fn update_credential_last_used(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE windows_audit_credentials SET last_used_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete credential (soft delete)
pub async fn delete_credential(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE windows_audit_credentials SET is_active = 0, updated_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// STIG Profile Operations
// ============================================================================

/// Get STIG profile by ID
pub async fn get_stig_profile(pool: &SqlitePool, id: &str) -> Result<Option<WindowsStigProfile>> {
    let profile = sqlx::query_as::<_, WindowsStigProfile>(
        "SELECT * FROM windows_stig_profiles WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(profile)
}

/// List STIG profiles
pub async fn list_stig_profiles(
    pool: &SqlitePool,
    os_type: Option<&str>,
) -> Result<Vec<WindowsStigProfile>> {
    let mut query = String::from("SELECT * FROM windows_stig_profiles WHERE 1=1");

    if let Some(os) = os_type {
        query.push_str(&format!(" AND os_type = '{}'", os));
    }

    query.push_str(" ORDER BY is_default DESC, name");

    let profiles = sqlx::query_as::<_, WindowsStigProfile>(&query)
        .fetch_all(pool)
        .await?;

    Ok(profiles)
}

/// Get default profile for OS type
pub async fn get_default_profile(
    pool: &SqlitePool,
    os_type: &str,
) -> Result<Option<WindowsStigProfile>> {
    let profile = sqlx::query_as::<_, WindowsStigProfile>(
        "SELECT * FROM windows_stig_profiles WHERE os_type = ?1 AND is_default = 1",
    )
    .bind(os_type)
    .fetch_optional(pool)
    .await?;

    Ok(profile)
}

/// Create custom STIG profile
pub async fn create_stig_profile(
    pool: &SqlitePool,
    profile: &WindowsStigProfile,
) -> Result<String> {
    let id = if profile.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        profile.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO windows_stig_profiles (
            id, name, description, os_type, stig_version, release_date,
            enabled_checks, disabled_checks, cat1_enabled, cat2_enabled, cat3_enabled,
            is_default, is_system, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(&id)
    .bind(&profile.name)
    .bind(&profile.description)
    .bind(&profile.os_type)
    .bind(&profile.stig_version)
    .bind(&profile.release_date)
    .bind(&profile.enabled_checks)
    .bind(&profile.disabled_checks)
    .bind(profile.cat1_enabled)
    .bind(profile.cat2_enabled)
    .bind(profile.cat3_enabled)
    .bind(false) // Not default
    .bind(false) // Not system
    .bind(&profile.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update STIG profile
pub async fn update_stig_profile(pool: &SqlitePool, profile: &WindowsStigProfile) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE windows_stig_profiles
        SET name = ?1, description = ?2, enabled_checks = ?3, disabled_checks = ?4,
            cat1_enabled = ?5, cat2_enabled = ?6, cat3_enabled = ?7, updated_at = ?8
        WHERE id = ?9 AND is_system = 0
        "#,
    )
    .bind(&profile.name)
    .bind(&profile.description)
    .bind(&profile.enabled_checks)
    .bind(&profile.disabled_checks)
    .bind(profile.cat1_enabled)
    .bind(profile.cat2_enabled)
    .bind(profile.cat3_enabled)
    .bind(&now)
    .bind(&profile.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete custom profile
pub async fn delete_stig_profile(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM windows_stig_profiles WHERE id = ?1 AND is_system = 0")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Result Operations
// ============================================================================

/// Create audit result
pub async fn create_result(pool: &SqlitePool, result: &WindowsAuditResult) -> Result<String> {
    let id = if result.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        result.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO windows_audit_results (
            id, scan_id, check_id, stig_id, cci_id, check_name, category,
            result, expected_value, actual_value, finding_details, fix_text,
            severity, check_type, evaluated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&result.scan_id)
    .bind(&result.check_id)
    .bind(&result.stig_id)
    .bind(&result.cci_id)
    .bind(&result.check_name)
    .bind(&result.category)
    .bind(&result.result)
    .bind(&result.expected_value)
    .bind(&result.actual_value)
    .bind(&result.finding_details)
    .bind(&result.fix_text)
    .bind(&result.severity)
    .bind(&result.check_type)
    .bind(&result.evaluated_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Batch insert results
pub async fn batch_insert_results(
    pool: &SqlitePool,
    results: &[WindowsAuditResult],
) -> Result<()> {
    for result in results {
        create_result(pool, result).await?;
    }
    Ok(())
}

/// Get results for scan
pub async fn get_results_for_scan(
    pool: &SqlitePool,
    scan_id: &str,
    category: Option<&str>,
    result_filter: Option<&str>,
) -> Result<Vec<WindowsAuditResult>> {
    let mut query = String::from("SELECT * FROM windows_audit_results WHERE scan_id = ?1");

    if let Some(cat) = category {
        query.push_str(&format!(" AND category = '{}'", cat));
    }
    if let Some(r) = result_filter {
        query.push_str(&format!(" AND result = '{}'", r));
    }

    query.push_str(" ORDER BY category, check_id");

    let results = sqlx::query_as::<_, WindowsAuditResult>(&query)
        .bind(scan_id)
        .fetch_all(pool)
        .await?;

    Ok(results)
}

/// Get result summary for scan
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultSummary {
    pub category: String,
    pub total: i64,
    pub passed: i64,
    pub failed: i64,
    pub errors: i64,
    pub not_applicable: i64,
}

pub async fn get_result_summary(pool: &SqlitePool, scan_id: &str) -> Result<Vec<ResultSummary>> {
    let summaries = sqlx::query_as::<_, (String, i64, i64, i64, i64, i64)>(
        r#"
        SELECT
            category,
            COUNT(*) as total,
            SUM(CASE WHEN result = 'pass' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN result = 'fail' THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN result = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN result = 'not_applicable' THEN 1 ELSE 0 END) as not_applicable
        FROM windows_audit_results
        WHERE scan_id = ?1
        GROUP BY category
        ORDER BY category
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(summaries
        .into_iter()
        .map(|(category, total, passed, failed, errors, not_applicable)| ResultSummary {
            category,
            total,
            passed,
            failed,
            errors,
            not_applicable,
        })
        .collect())
}

// ============================================================================
// Snapshot Operations
// ============================================================================

/// Create system snapshot
pub async fn create_snapshot(pool: &SqlitePool, snapshot: &WindowsSystemSnapshot) -> Result<String> {
    let id = if snapshot.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        snapshot.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO windows_system_snapshots (
            id, scan_id, snapshot_type, snapshot_data, collected_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(&id)
    .bind(&snapshot.scan_id)
    .bind(&snapshot.snapshot_type)
    .bind(&snapshot.snapshot_data)
    .bind(&snapshot.collected_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get snapshots for scan
pub async fn get_snapshots_for_scan(
    pool: &SqlitePool,
    scan_id: &str,
    snapshot_type: Option<&str>,
) -> Result<Vec<WindowsSystemSnapshot>> {
    let mut query = String::from("SELECT * FROM windows_system_snapshots WHERE scan_id = ?1");

    if let Some(st) = snapshot_type {
        query.push_str(&format!(" AND snapshot_type = '{}'", st));
    }

    query.push_str(" ORDER BY collected_at");

    let snapshots = sqlx::query_as::<_, WindowsSystemSnapshot>(&query)
        .bind(scan_id)
        .fetch_all(pool)
        .await?;

    Ok(snapshots)
}

// ============================================================================
// Schedule Operations
// ============================================================================

/// Create audit schedule
pub async fn create_schedule(pool: &SqlitePool, schedule: &WindowsAuditSchedule) -> Result<String> {
    let id = if schedule.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        schedule.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO windows_audit_schedules (
            id, name, description, target_hosts, credential_id, stig_profile_id,
            cron_expression, timezone, is_active, next_run_at, last_run_at,
            created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&id)
    .bind(&schedule.name)
    .bind(&schedule.description)
    .bind(&schedule.target_hosts)
    .bind(&schedule.credential_id)
    .bind(&schedule.stig_profile_id)
    .bind(&schedule.cron_expression)
    .bind(&schedule.timezone)
    .bind(schedule.is_active)
    .bind(&schedule.next_run_at)
    .bind(&schedule.last_run_at)
    .bind(&schedule.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get due schedules
pub async fn get_due_schedules(pool: &SqlitePool) -> Result<Vec<WindowsAuditSchedule>> {
    let now = Utc::now().to_rfc3339();

    let schedules = sqlx::query_as::<_, WindowsAuditSchedule>(
        r#"
        SELECT * FROM windows_audit_schedules
        WHERE is_active = 1 AND (next_run_at IS NULL OR next_run_at <= ?1)
        ORDER BY next_run_at
        "#,
    )
    .bind(&now)
    .fetch_all(pool)
    .await?;

    Ok(schedules)
}

/// Update schedule next run
pub async fn update_schedule_next_run(
    pool: &SqlitePool,
    id: &str,
    next_run_at: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE windows_audit_schedules
        SET next_run_at = ?1, last_run_at = ?2, updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(next_run_at)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}
