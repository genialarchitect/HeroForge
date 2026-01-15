//! Database operations for audit file management (CKL/ARF)
//!
//! This module provides CRUD operations for audit files, version history,
//! evidence linking, and retention policy management.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Audit file database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditFile {
    pub id: String,
    pub file_type: String, // "ckl", "arf", "xccdf_results"
    pub framework: String, // "disa_stig", "scap", "cis"
    pub benchmark_name: Option<String>,
    pub benchmark_version: Option<String>,
    pub profile_name: Option<String>,
    pub filename: String,
    pub file_size: i64,
    pub content_hash: String,
    pub file_path: Option<String>,
    pub content: Option<String>, // Optional inline content
    pub target_host: Option<String>,
    pub target_ip: Option<String>,
    pub scan_id: Option<String>,
    pub execution_id: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub total_checks: i32,
    pub passed_checks: i32,
    pub failed_checks: i32,
    pub not_applicable: i32,
    pub not_reviewed: i32,
    pub compliance_score: Option<f64>,
    pub version: i32,
    pub is_latest: bool,
    pub previous_version_id: Option<String>,
    pub retention_days: i32,
    pub expires_at: Option<String>,
    pub generated_by: String,
    pub generated_at: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Audit file version history record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditFileVersion {
    pub id: String,
    pub audit_file_id: String,
    pub version: i32,
    pub filename: String,
    pub file_size: i64,
    pub content_hash: String,
    pub file_path: Option<String>,
    pub total_checks: i32,
    pub passed_checks: i32,
    pub failed_checks: i32,
    pub not_applicable: i32,
    pub compliance_score: Option<f64>,
    pub change_summary: Option<String>,
    pub generated_by: String,
    pub generated_at: String,
    pub created_at: String,
}

/// Audit file evidence link record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditFileEvidenceLink {
    pub id: String,
    pub audit_file_id: String,
    pub evidence_id: String,
    pub control_id: Option<String>,
    pub framework_id: Option<String>,
    pub link_type: String, // "source", "supporting", "derived"
    pub notes: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

/// Audit file access log record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditFileAccessLog {
    pub id: String,
    pub audit_file_id: String,
    pub action: String, // "view", "download", "export", "modify", "delete"
    pub user_id: String,
    pub user_ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub accessed_at: String,
}

/// Retention policy record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub framework: Option<String>,
    pub file_type: Option<String>,
    pub retention_days: i32,
    pub auto_delete: bool,
    pub notify_before_days: i32,
    pub is_default: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Import record for tracking imported audit files
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditFileImport {
    pub id: String,
    pub original_filename: String,
    pub file_type: String,
    pub import_status: String, // "pending", "processing", "completed", "failed"
    pub audit_file_id: Option<String>,
    pub error_message: Option<String>,
    pub parsed_data: Option<String>, // JSON summary of parsed content
    pub imported_by: String,
    pub imported_at: String,
}

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize audit file database tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // Audit files
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_files (
            id TEXT PRIMARY KEY,
            file_type TEXT NOT NULL,
            framework TEXT NOT NULL,
            benchmark_name TEXT,
            benchmark_version TEXT,
            profile_name TEXT,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            file_path TEXT,
            content TEXT,
            target_host TEXT,
            target_ip TEXT,
            scan_id TEXT,
            execution_id TEXT,
            customer_id TEXT,
            engagement_id TEXT,
            total_checks INTEGER NOT NULL DEFAULT 0,
            passed_checks INTEGER NOT NULL DEFAULT 0,
            failed_checks INTEGER NOT NULL DEFAULT 0,
            not_applicable INTEGER NOT NULL DEFAULT 0,
            not_reviewed INTEGER NOT NULL DEFAULT 0,
            compliance_score REAL,
            version INTEGER NOT NULL DEFAULT 1,
            is_latest INTEGER NOT NULL DEFAULT 1,
            previous_version_id TEXT,
            retention_days INTEGER NOT NULL DEFAULT 2555,
            expires_at TEXT,
            generated_by TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Audit file versions
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_file_versions (
            id TEXT PRIMARY KEY,
            audit_file_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            file_path TEXT,
            total_checks INTEGER NOT NULL DEFAULT 0,
            passed_checks INTEGER NOT NULL DEFAULT 0,
            failed_checks INTEGER NOT NULL DEFAULT 0,
            not_applicable INTEGER NOT NULL DEFAULT 0,
            compliance_score REAL,
            change_summary TEXT,
            generated_by TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (audit_file_id) REFERENCES audit_files(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Audit file evidence links
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_file_evidence_links (
            id TEXT PRIMARY KEY,
            audit_file_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            control_id TEXT,
            framework_id TEXT,
            link_type TEXT NOT NULL,
            notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (audit_file_id) REFERENCES audit_files(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Audit file access log
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_file_access_log (
            id TEXT PRIMARY KEY,
            audit_file_id TEXT NOT NULL,
            action TEXT NOT NULL,
            user_id TEXT NOT NULL,
            user_ip TEXT,
            user_agent TEXT,
            details TEXT,
            accessed_at TEXT NOT NULL,
            FOREIGN KEY (audit_file_id) REFERENCES audit_files(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Retention policies
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_file_retention_policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            framework TEXT,
            file_type TEXT,
            retention_days INTEGER NOT NULL,
            auto_delete INTEGER NOT NULL DEFAULT 0,
            notify_before_days INTEGER NOT NULL DEFAULT 30,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Audit file imports
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_file_imports (
            id TEXT PRIMARY KEY,
            original_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            import_status TEXT NOT NULL,
            audit_file_id TEXT,
            error_message TEXT,
            parsed_data TEXT,
            imported_by TEXT NOT NULL,
            imported_at TEXT NOT NULL,
            FOREIGN KEY (audit_file_id) REFERENCES audit_files(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_files_type ON audit_files(file_type)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_files_framework ON audit_files(framework)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_files_scan ON audit_files(scan_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_files_customer ON audit_files(customer_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_files_hash ON audit_files(content_hash)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_file_versions_file ON audit_file_versions(audit_file_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_file_evidence_file ON audit_file_evidence_links(audit_file_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_file_access_file ON audit_file_access_log(audit_file_id)")
        .execute(pool)
        .await?;

    // Insert default retention policies
    insert_default_policies(pool).await?;

    Ok(())
}

/// Insert default retention policies
async fn insert_default_policies(pool: &SqlitePool) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    // Check if default policies already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_file_retention_policies WHERE is_default = 1")
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    if count.0 > 0 {
        return Ok(());
    }

    // Federal compliance default (7 years)
    sqlx::query(
        r#"
        INSERT INTO audit_file_retention_policies (
            id, name, description, framework, file_type, retention_days,
            auto_delete, notify_before_days, is_default, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("Federal Compliance (7 Years)")
    .bind("Default retention policy for federal compliance requirements (NIST, FedRAMP, FISMA)")
    .bind::<Option<&str>>(None) // All frameworks
    .bind::<Option<&str>>(None) // All file types
    .bind(2555) // 7 years
    .bind(false)
    .bind(90) // Notify 90 days before
    .bind(true) // Is default
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // HIPAA (6 years)
    sqlx::query(
        r#"
        INSERT INTO audit_file_retention_policies (
            id, name, description, framework, file_type, retention_days,
            auto_delete, notify_before_days, is_default, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("HIPAA Compliance (6 Years)")
    .bind("Retention policy for HIPAA compliance documentation")
    .bind("hipaa")
    .bind::<Option<&str>>(None)
    .bind(2190) // 6 years
    .bind(false)
    .bind(60)
    .bind(false)
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    // PCI-DSS (1 year)
    sqlx::query(
        r#"
        INSERT INTO audit_file_retention_policies (
            id, name, description, framework, file_type, retention_days,
            auto_delete, notify_before_days, is_default, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind("PCI-DSS (1 Year)")
    .bind("Minimum retention policy for PCI-DSS compliance")
    .bind("pci_dss")
    .bind::<Option<&str>>(None)
    .bind(365) // 1 year
    .bind(false)
    .bind(30)
    .bind(false)
    .bind("system")
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Audit File Operations
// ============================================================================

/// Create a new audit file record
pub async fn create_audit_file(pool: &SqlitePool, file: &AuditFile) -> Result<String> {
    let id = if file.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        file.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    // Calculate expiration date
    let expires_at = if file.retention_days > 0 {
        let expiry = Utc::now() + chrono::Duration::days(file.retention_days as i64);
        Some(expiry.to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        INSERT INTO audit_files (
            id, file_type, framework, benchmark_name, benchmark_version, profile_name,
            filename, file_size, content_hash, file_path, content, target_host, target_ip,
            scan_id, execution_id, customer_id, engagement_id, total_checks, passed_checks,
            failed_checks, not_applicable, not_reviewed, compliance_score, version, is_latest,
            previous_version_id, retention_days, expires_at, generated_by, generated_at,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32)
        "#,
    )
    .bind(&id)
    .bind(&file.file_type)
    .bind(&file.framework)
    .bind(&file.benchmark_name)
    .bind(&file.benchmark_version)
    .bind(&file.profile_name)
    .bind(&file.filename)
    .bind(file.file_size)
    .bind(&file.content_hash)
    .bind(&file.file_path)
    .bind(&file.content)
    .bind(&file.target_host)
    .bind(&file.target_ip)
    .bind(&file.scan_id)
    .bind(&file.execution_id)
    .bind(&file.customer_id)
    .bind(&file.engagement_id)
    .bind(file.total_checks)
    .bind(file.passed_checks)
    .bind(file.failed_checks)
    .bind(file.not_applicable)
    .bind(file.not_reviewed)
    .bind(file.compliance_score)
    .bind(file.version)
    .bind(file.is_latest)
    .bind(&file.previous_version_id)
    .bind(file.retention_days)
    .bind(&expires_at)
    .bind(&file.generated_by)
    .bind(&file.generated_at)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get audit file by ID
pub async fn get_audit_file(pool: &SqlitePool, id: &str) -> Result<Option<AuditFile>> {
    let file = sqlx::query_as::<_, AuditFile>(
        "SELECT * FROM audit_files WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(file)
}

/// Get audit file by hash (to check for duplicates)
pub async fn get_audit_file_by_hash(pool: &SqlitePool, content_hash: &str) -> Result<Option<AuditFile>> {
    let file = sqlx::query_as::<_, AuditFile>(
        "SELECT * FROM audit_files WHERE content_hash = ?1 AND is_latest = 1",
    )
    .bind(content_hash)
    .fetch_optional(pool)
    .await?;

    Ok(file)
}

/// List audit files with filters
pub async fn list_audit_files(
    pool: &SqlitePool,
    file_type: Option<&str>,
    framework: Option<&str>,
    customer_id: Option<&str>,
    scan_id: Option<&str>,
    latest_only: bool,
    limit: i32,
    offset: i32,
) -> Result<(Vec<AuditFile>, i64)> {
    let mut where_clauses = vec!["1=1".to_string()];

    if let Some(ft) = file_type {
        where_clauses.push(format!("file_type = '{}'", ft));
    }
    if let Some(fw) = framework {
        where_clauses.push(format!("framework = '{}'", fw));
    }
    if let Some(cid) = customer_id {
        where_clauses.push(format!("customer_id = '{}'", cid));
    }
    if let Some(sid) = scan_id {
        where_clauses.push(format!("scan_id = '{}'", sid));
    }
    if latest_only {
        where_clauses.push("is_latest = 1".to_string());
    }

    let where_sql = where_clauses.join(" AND ");

    // Get count
    let count_query = format!("SELECT COUNT(*) FROM audit_files WHERE {}", where_sql);
    let total: (i64,) = sqlx::query_as(&count_query)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    // Get files
    let select_query = format!(
        "SELECT * FROM audit_files WHERE {} ORDER BY generated_at DESC LIMIT {} OFFSET {}",
        where_sql, limit, offset
    );
    let files = sqlx::query_as::<_, AuditFile>(&select_query)
        .fetch_all(pool)
        .await?;

    Ok((files, total.0))
}

/// Update audit file
pub async fn update_audit_file(pool: &SqlitePool, file: &AuditFile) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE audit_files
        SET benchmark_name = ?1, benchmark_version = ?2, profile_name = ?3,
            target_host = ?4, target_ip = ?5, customer_id = ?6, engagement_id = ?7,
            retention_days = ?8, updated_at = ?9
        WHERE id = ?10
        "#,
    )
    .bind(&file.benchmark_name)
    .bind(&file.benchmark_version)
    .bind(&file.profile_name)
    .bind(&file.target_host)
    .bind(&file.target_ip)
    .bind(&file.customer_id)
    .bind(&file.engagement_id)
    .bind(file.retention_days)
    .bind(&now)
    .bind(&file.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete audit file
pub async fn delete_audit_file(pool: &SqlitePool, id: &str) -> Result<()> {
    // Delete related records first
    sqlx::query("DELETE FROM audit_file_evidence_links WHERE audit_file_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM audit_file_versions WHERE audit_file_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM audit_file_access_log WHERE audit_file_id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM audit_files WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Create new version of audit file
pub async fn create_new_version(
    pool: &SqlitePool,
    original_id: &str,
    new_file: &AuditFile,
    change_summary: Option<&str>,
) -> Result<String> {
    // Get original file
    let original = get_audit_file(pool, original_id).await?
        .ok_or_else(|| anyhow::anyhow!("Original audit file not found"))?;

    // Save current version to history
    let version_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO audit_file_versions (
            id, audit_file_id, version, filename, file_size, content_hash,
            file_path, total_checks, passed_checks, failed_checks, not_applicable,
            compliance_score, change_summary, generated_by, generated_at, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
        "#,
    )
    .bind(&version_id)
    .bind(original_id)
    .bind(original.version)
    .bind(&original.filename)
    .bind(original.file_size)
    .bind(&original.content_hash)
    .bind(&original.file_path)
    .bind(original.total_checks)
    .bind(original.passed_checks)
    .bind(original.failed_checks)
    .bind(original.not_applicable)
    .bind(original.compliance_score)
    .bind(change_summary)
    .bind(&original.generated_by)
    .bind(&original.generated_at)
    .bind(&now)
    .execute(pool)
    .await?;

    // Update original file with new data
    let new_version = original.version + 1;
    let expires_at = if new_file.retention_days > 0 {
        let expiry = Utc::now() + chrono::Duration::days(new_file.retention_days as i64);
        Some(expiry.to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE audit_files
        SET filename = ?1, file_size = ?2, content_hash = ?3, file_path = ?4,
            content = ?5, total_checks = ?6, passed_checks = ?7, failed_checks = ?8,
            not_applicable = ?9, not_reviewed = ?10, compliance_score = ?11,
            version = ?12, previous_version_id = ?13, expires_at = ?14,
            generated_by = ?15, generated_at = ?16, updated_at = ?17
        WHERE id = ?18
        "#,
    )
    .bind(&new_file.filename)
    .bind(new_file.file_size)
    .bind(&new_file.content_hash)
    .bind(&new_file.file_path)
    .bind(&new_file.content)
    .bind(new_file.total_checks)
    .bind(new_file.passed_checks)
    .bind(new_file.failed_checks)
    .bind(new_file.not_applicable)
    .bind(new_file.not_reviewed)
    .bind(new_file.compliance_score)
    .bind(new_version)
    .bind(&version_id)
    .bind(&expires_at)
    .bind(&new_file.generated_by)
    .bind(&new_file.generated_at)
    .bind(&now)
    .bind(original_id)
    .execute(pool)
    .await?;

    Ok(original_id.to_string())
}

/// Get version history for audit file
pub async fn get_version_history(pool: &SqlitePool, audit_file_id: &str) -> Result<Vec<AuditFileVersion>> {
    let versions = sqlx::query_as::<_, AuditFileVersion>(
        "SELECT * FROM audit_file_versions WHERE audit_file_id = ?1 ORDER BY version DESC",
    )
    .bind(audit_file_id)
    .fetch_all(pool)
    .await?;

    Ok(versions)
}

// ============================================================================
// Evidence Link Operations
// ============================================================================

/// Create evidence link
pub async fn create_evidence_link(pool: &SqlitePool, link: &AuditFileEvidenceLink) -> Result<String> {
    let id = if link.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        link.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO audit_file_evidence_links (
            id, audit_file_id, evidence_id, control_id, framework_id,
            link_type, notes, created_by, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&link.audit_file_id)
    .bind(&link.evidence_id)
    .bind(&link.control_id)
    .bind(&link.framework_id)
    .bind(&link.link_type)
    .bind(&link.notes)
    .bind(&link.created_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get evidence links for audit file
pub async fn get_evidence_links(pool: &SqlitePool, audit_file_id: &str) -> Result<Vec<AuditFileEvidenceLink>> {
    let links = sqlx::query_as::<_, AuditFileEvidenceLink>(
        "SELECT * FROM audit_file_evidence_links WHERE audit_file_id = ?1",
    )
    .bind(audit_file_id)
    .fetch_all(pool)
    .await?;

    Ok(links)
}

/// Delete evidence link
pub async fn delete_evidence_link(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM audit_file_evidence_links WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Access Log Operations
// ============================================================================

/// Log access to audit file
pub async fn log_access(
    pool: &SqlitePool,
    audit_file_id: &str,
    action: &str,
    user_id: &str,
    user_ip: Option<&str>,
    user_agent: Option<&str>,
    details: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO audit_file_access_log (
            id, audit_file_id, action, user_id, user_ip, user_agent, details, accessed_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
    )
    .bind(&id)
    .bind(audit_file_id)
    .bind(action)
    .bind(user_id)
    .bind(user_ip)
    .bind(user_agent)
    .bind(details)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get access log for audit file
pub async fn get_access_log(
    pool: &SqlitePool,
    audit_file_id: &str,
    limit: i32,
) -> Result<Vec<AuditFileAccessLog>> {
    let logs = sqlx::query_as::<_, AuditFileAccessLog>(
        "SELECT * FROM audit_file_access_log WHERE audit_file_id = ?1 ORDER BY accessed_at DESC LIMIT ?2",
    )
    .bind(audit_file_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}

// ============================================================================
// Retention Policy Operations
// ============================================================================

/// Get retention policy by ID
pub async fn get_retention_policy(pool: &SqlitePool, id: &str) -> Result<Option<RetentionPolicy>> {
    let policy = sqlx::query_as::<_, RetentionPolicy>(
        "SELECT * FROM audit_file_retention_policies WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(policy)
}

/// Get default retention policy
pub async fn get_default_retention_policy(pool: &SqlitePool) -> Result<Option<RetentionPolicy>> {
    let policy = sqlx::query_as::<_, RetentionPolicy>(
        "SELECT * FROM audit_file_retention_policies WHERE is_default = 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(policy)
}

/// Get retention policy for framework
pub async fn get_retention_policy_for_framework(
    pool: &SqlitePool,
    framework: &str,
) -> Result<Option<RetentionPolicy>> {
    let policy = sqlx::query_as::<_, RetentionPolicy>(
        "SELECT * FROM audit_file_retention_policies WHERE framework = ?1",
    )
    .bind(framework)
    .fetch_optional(pool)
    .await?;

    Ok(policy)
}

/// List all retention policies
pub async fn list_retention_policies(pool: &SqlitePool) -> Result<Vec<RetentionPolicy>> {
    let policies = sqlx::query_as::<_, RetentionPolicy>(
        "SELECT * FROM audit_file_retention_policies ORDER BY is_default DESC, name",
    )
    .fetch_all(pool)
    .await?;

    Ok(policies)
}

/// Create retention policy
pub async fn create_retention_policy(pool: &SqlitePool, policy: &RetentionPolicy) -> Result<String> {
    let id = if policy.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        policy.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO audit_file_retention_policies (
            id, name, description, framework, file_type, retention_days,
            auto_delete, notify_before_days, is_default, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
    )
    .bind(&id)
    .bind(&policy.name)
    .bind(&policy.description)
    .bind(&policy.framework)
    .bind(&policy.file_type)
    .bind(policy.retention_days)
    .bind(policy.auto_delete)
    .bind(policy.notify_before_days)
    .bind(policy.is_default)
    .bind(&policy.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get files expiring soon
pub async fn get_expiring_files(pool: &SqlitePool, days_until_expiry: i32) -> Result<Vec<AuditFile>> {
    let cutoff = Utc::now() + chrono::Duration::days(days_until_expiry as i64);

    let files = sqlx::query_as::<_, AuditFile>(
        r#"
        SELECT * FROM audit_files
        WHERE expires_at IS NOT NULL AND expires_at <= ?1 AND is_latest = 1
        ORDER BY expires_at
        "#,
    )
    .bind(cutoff.to_rfc3339())
    .fetch_all(pool)
    .await?;

    Ok(files)
}

/// Get expired files for cleanup
pub async fn get_expired_files(pool: &SqlitePool) -> Result<Vec<AuditFile>> {
    let now = Utc::now().to_rfc3339();

    let files = sqlx::query_as::<_, AuditFile>(
        r#"
        SELECT * FROM audit_files
        WHERE expires_at IS NOT NULL AND expires_at <= ?1
        "#,
    )
    .bind(&now)
    .fetch_all(pool)
    .await?;

    Ok(files)
}

// ============================================================================
// Import Operations
// ============================================================================

/// Create import record
pub async fn create_import(pool: &SqlitePool, import_record: &AuditFileImport) -> Result<String> {
    let id = if import_record.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        import_record.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO audit_file_imports (
            id, original_filename, file_type, import_status, audit_file_id,
            error_message, parsed_data, imported_by, imported_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
    )
    .bind(&id)
    .bind(&import_record.original_filename)
    .bind(&import_record.file_type)
    .bind(&import_record.import_status)
    .bind(&import_record.audit_file_id)
    .bind(&import_record.error_message)
    .bind(&import_record.parsed_data)
    .bind(&import_record.imported_by)
    .bind(&import_record.imported_at)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update import status
pub async fn update_import_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    audit_file_id: Option<&str>,
    error_message: Option<&str>,
    parsed_data: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        UPDATE audit_file_imports
        SET import_status = ?1, audit_file_id = ?2, error_message = ?3, parsed_data = ?4
        WHERE id = ?5
        "#,
    )
    .bind(status)
    .bind(audit_file_id)
    .bind(error_message)
    .bind(parsed_data)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get recent imports
pub async fn get_recent_imports(pool: &SqlitePool, limit: i32) -> Result<Vec<AuditFileImport>> {
    let imports = sqlx::query_as::<_, AuditFileImport>(
        "SELECT * FROM audit_file_imports ORDER BY imported_at DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(imports)
}

// ============================================================================
// Statistics
// ============================================================================

/// Audit file statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditFileStats {
    pub total_files: i64,
    pub total_by_type: Vec<(String, i64)>,
    pub total_by_framework: Vec<(String, i64)>,
    pub files_expiring_30_days: i64,
    pub average_compliance_score: Option<f64>,
    pub total_size_bytes: i64,
}

/// Get audit file statistics
pub async fn get_statistics(pool: &SqlitePool, customer_id: Option<&str>) -> Result<AuditFileStats> {
    let mut where_clause = "WHERE is_latest = 1".to_string();
    if let Some(cid) = customer_id {
        where_clause.push_str(&format!(" AND customer_id = '{}'", cid));
    }

    // Total files
    let total_query = format!("SELECT COUNT(*) FROM audit_files {}", where_clause);
    let total_files: (i64,) = sqlx::query_as(&total_query)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    // By type
    let type_query = format!(
        "SELECT file_type, COUNT(*) FROM audit_files {} GROUP BY file_type",
        where_clause
    );
    let total_by_type: Vec<(String, i64)> = sqlx::query_as(&type_query)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    // By framework
    let framework_query = format!(
        "SELECT framework, COUNT(*) FROM audit_files {} GROUP BY framework",
        where_clause
    );
    let total_by_framework: Vec<(String, i64)> = sqlx::query_as(&framework_query)
        .fetch_all(pool)
        .await
        .unwrap_or_default();

    // Expiring in 30 days
    let cutoff = Utc::now() + chrono::Duration::days(30);
    let expiring_query = format!(
        "SELECT COUNT(*) FROM audit_files {} AND expires_at IS NOT NULL AND expires_at <= ?1",
        where_clause
    );
    let files_expiring: (i64,) = sqlx::query_as(&expiring_query)
        .bind(cutoff.to_rfc3339())
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    // Average compliance score
    let score_query = format!(
        "SELECT AVG(compliance_score) FROM audit_files {} AND compliance_score IS NOT NULL",
        where_clause
    );
    let avg_score: (Option<f64>,) = sqlx::query_as(&score_query)
        .fetch_one(pool)
        .await
        .unwrap_or((None,));

    // Total size
    let size_query = format!("SELECT COALESCE(SUM(file_size), 0) FROM audit_files {}", where_clause);
    let total_size: (i64,) = sqlx::query_as(&size_query)
        .fetch_one(pool)
        .await
        .unwrap_or((0,));

    Ok(AuditFileStats {
        total_files: total_files.0,
        total_by_type,
        total_by_framework,
        files_expiring_30_days: files_expiring.0,
        average_compliance_score: avg_score.0,
        total_size_bytes: total_size.0,
    })
}
