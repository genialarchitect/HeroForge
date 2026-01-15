//! Audit File Library
//!
//! Manages CKL and ARF audit files with versioning, retention policies,
//! and chain of custody tracking for compliance documentation.

use anyhow::{Result, Context};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use sqlx::{SqlitePool, Row, FromRow};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

/// Audit file types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditFileType {
    /// DISA STIG Viewer Checklist
    Ckl,
    /// SCAP Asset Reporting Format
    Arf,
    /// XCCDF Results
    Xccdf,
    /// OVAL Results
    Oval,
}

impl AuditFileType {
    pub fn extension(&self) -> &'static str {
        match self {
            AuditFileType::Ckl => "ckl",
            AuditFileType::Arf => "xml",
            AuditFileType::Xccdf => "xml",
            AuditFileType::Oval => "xml",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            AuditFileType::Ckl => "DISA STIG Viewer Checklist",
            AuditFileType::Arf => "SCAP Asset Reporting Format",
            AuditFileType::Xccdf => "XCCDF Test Results",
            AuditFileType::Oval => "OVAL Definition Results",
        }
    }
}

impl std::fmt::Display for AuditFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditFileType::Ckl => write!(f, "ckl"),
            AuditFileType::Arf => write!(f, "arf"),
            AuditFileType::Xccdf => write!(f, "xccdf"),
            AuditFileType::Oval => write!(f, "oval"),
        }
    }
}

/// Audit file metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFile {
    pub id: String,
    pub file_type: AuditFileType,
    pub filename: String,
    pub file_path: String,
    pub file_size: i64,
    pub sha256_hash: String,
    pub version: i32,
    pub system_id: Option<String>,
    pub asset_id: Option<String>,
    pub framework: Option<String>,
    pub profile_id: Option<String>,
    pub scan_id: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub retention_until: Option<DateTime<Utc>>,
    pub is_archived: bool,
    pub notes: Option<String>,
}

/// Audit file version history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFileVersion {
    pub id: String,
    pub audit_file_id: String,
    pub version: i32,
    pub file_path: String,
    pub file_size: i64,
    pub sha256_hash: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub change_summary: Option<String>,
}

/// Chain of custody event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    pub id: String,
    pub audit_file_id: String,
    pub event_type: CustodyEventType,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub details: Option<String>,
    pub ip_address: Option<String>,
}

/// Types of custody events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyEventType {
    Created,
    Viewed,
    Downloaded,
    Modified,
    Archived,
    Restored,
    Deleted,
    Exported,
    Imported,
    Verified,
}

impl std::fmt::Display for CustodyEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyEventType::Created => write!(f, "created"),
            CustodyEventType::Viewed => write!(f, "viewed"),
            CustodyEventType::Downloaded => write!(f, "downloaded"),
            CustodyEventType::Modified => write!(f, "modified"),
            CustodyEventType::Archived => write!(f, "archived"),
            CustodyEventType::Restored => write!(f, "restored"),
            CustodyEventType::Deleted => write!(f, "deleted"),
            CustodyEventType::Exported => write!(f, "exported"),
            CustodyEventType::Imported => write!(f, "imported"),
            CustodyEventType::Verified => write!(f, "verified"),
        }
    }
}

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub file_type: Option<AuditFileType>,
    pub framework: Option<String>,
    pub retention_days: i32,
    pub auto_archive: bool,
    pub auto_delete: bool,
    pub is_default: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Federal Default".to_string(),
            description: Some("7-year retention for federal compliance".to_string()),
            file_type: None,
            framework: None,
            retention_days: 2555, // ~7 years
            auto_archive: true,
            auto_delete: false,
            is_default: true,
        }
    }
}

/// Audit file library manager
pub struct AuditLibrary {
    pool: SqlitePool,
    storage_dir: String,
}

impl AuditLibrary {
    /// Create a new audit library manager
    pub fn new(pool: SqlitePool, storage_dir: &str) -> Self {
        Self {
            pool,
            storage_dir: storage_dir.to_string(),
        }
    }

    /// Store a new audit file
    pub async fn store_file(
        &self,
        content: &[u8],
        file_type: AuditFileType,
        filename: &str,
        created_by: &str,
        metadata: AuditFileMetadata,
    ) -> Result<AuditFile> {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = format!("{:x}", hasher.finalize());

        // Create storage path
        let file_id = Uuid::new_v4().to_string();
        let storage_path = format!(
            "{}/{}/{}.{}",
            self.storage_dir,
            file_type,
            file_id,
            file_type.extension()
        );

        // Ensure directory exists
        if let Some(parent) = Path::new(&storage_path).parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write file
        fs::write(&storage_path, content).await?;

        // Get retention policy
        let retention_until = self.calculate_retention_date(
            file_type,
            metadata.framework.as_deref(),
        ).await?;

        let audit_file = AuditFile {
            id: file_id.clone(),
            file_type,
            filename: filename.to_string(),
            file_path: storage_path.clone(),
            file_size: content.len() as i64,
            sha256_hash: hash.clone(),
            version: 1,
            system_id: metadata.system_id,
            asset_id: metadata.asset_id,
            framework: metadata.framework,
            profile_id: metadata.profile_id,
            scan_id: metadata.scan_id,
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            retention_until,
            is_archived: false,
            notes: metadata.notes,
        };

        // Insert into database
        self.insert_audit_file(&audit_file).await?;

        // Create initial version
        let version = AuditFileVersion {
            id: Uuid::new_v4().to_string(),
            audit_file_id: file_id.clone(),
            version: 1,
            file_path: storage_path,
            file_size: content.len() as i64,
            sha256_hash: hash,
            created_by: created_by.to_string(),
            created_at: Utc::now(),
            change_summary: Some("Initial version".to_string()),
        };
        self.insert_version(&version).await?;

        // Log custody event
        self.log_custody_event(
            &file_id,
            CustodyEventType::Created,
            created_by,
            Some("File created and stored"),
            None,
        ).await?;

        Ok(audit_file)
    }

    /// Get audit file by ID
    pub async fn get_file(&self, file_id: &str) -> Result<Option<AuditFile>> {
        let row = sqlx::query_as::<_, AuditFileRow>(
            r#"
            SELECT id, file_type, filename, file_path, file_size, sha256_hash,
                   version, system_id, asset_id, framework, profile_id, scan_id,
                   created_by, created_at, retention_until, is_archived, notes
            FROM audit_files
            WHERE id = ?
            "#
        )
        .bind(file_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// List audit files with filters
    pub async fn list_files(
        &self,
        filters: AuditFileFilters,
    ) -> Result<Vec<AuditFile>> {
        let mut query = String::from(
            "SELECT id, file_type, filename, file_path, file_size, sha256_hash,
                    version, system_id, asset_id, framework, profile_id, scan_id,
                    created_by, created_at, retention_until, is_archived, notes
             FROM audit_files WHERE 1=1"
        );

        if let Some(ref file_type) = filters.file_type {
            query.push_str(&format!(" AND file_type = '{}'", file_type));
        }
        if let Some(ref framework) = filters.framework {
            query.push_str(&format!(" AND framework = '{}'", framework));
        }
        if let Some(ref system_id) = filters.system_id {
            query.push_str(&format!(" AND system_id = '{}'", system_id));
        }
        if filters.archived_only {
            query.push_str(" AND is_archived = 1");
        } else if !filters.include_archived {
            query.push_str(" AND is_archived = 0");
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let rows = sqlx::query_as::<_, AuditFileRow>(&query)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Update audit file with new version
    pub async fn update_file(
        &self,
        file_id: &str,
        content: &[u8],
        updated_by: &str,
        change_summary: Option<&str>,
    ) -> Result<AuditFile> {
        let existing = self.get_file(file_id).await?
            .ok_or_else(|| anyhow::anyhow!("Audit file not found: {}", file_id))?;

        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = format!("{:x}", hasher.finalize());

        // Create new version path
        let new_version = existing.version + 1;
        let storage_path = format!(
            "{}/{}/{}_v{}.{}",
            self.storage_dir,
            existing.file_type,
            file_id,
            new_version,
            existing.file_type.extension()
        );

        // Write new version
        fs::write(&storage_path, content).await?;

        // Update main record
        sqlx::query(
            r#"
            UPDATE audit_files
            SET version = ?, file_path = ?, file_size = ?, sha256_hash = ?
            WHERE id = ?
            "#
        )
        .bind(new_version)
        .bind(&storage_path)
        .bind(content.len() as i64)
        .bind(&hash)
        .bind(file_id)
        .execute(&self.pool)
        .await?;

        // Insert version record
        let version = AuditFileVersion {
            id: Uuid::new_v4().to_string(),
            audit_file_id: file_id.to_string(),
            version: new_version,
            file_path: storage_path,
            file_size: content.len() as i64,
            sha256_hash: hash,
            created_by: updated_by.to_string(),
            created_at: Utc::now(),
            change_summary: change_summary.map(String::from),
        };
        self.insert_version(&version).await?;

        // Log custody event
        self.log_custody_event(
            file_id,
            CustodyEventType::Modified,
            updated_by,
            change_summary,
            None,
        ).await?;

        self.get_file(file_id).await?.ok_or_else(|| anyhow::anyhow!("File not found after update"))
    }

    /// Get version history for a file
    pub async fn get_versions(&self, file_id: &str) -> Result<Vec<AuditFileVersion>> {
        let rows = sqlx::query_as::<_, AuditFileVersionRow>(
            r#"
            SELECT id, audit_file_id, version, file_path, file_size, sha256_hash,
                   created_by, created_at, change_summary
            FROM audit_file_versions
            WHERE audit_file_id = ?
            ORDER BY version DESC
            "#
        )
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|v| v.into()).collect())
    }

    /// Get chain of custody for a file
    pub async fn get_custody_chain(&self, file_id: &str) -> Result<Vec<CustodyEvent>> {
        let rows = sqlx::query_as::<_, CustodyEventRow>(
            r#"
            SELECT id, audit_file_id, event_type, actor, timestamp, details, ip_address
            FROM audit_custody_events
            WHERE audit_file_id = ?
            ORDER BY timestamp ASC
            "#
        )
        .bind(file_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|e| e.into()).collect())
    }

    /// Verify file integrity
    pub async fn verify_integrity(&self, file_id: &str, actor: &str) -> Result<bool> {
        let file = self.get_file(file_id).await?
            .ok_or_else(|| anyhow::anyhow!("Audit file not found: {}", file_id))?;

        let content = fs::read(&file.file_path).await
            .context("Failed to read audit file")?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let computed_hash = format!("{:x}", hasher.finalize());

        let is_valid = computed_hash == file.sha256_hash;

        // Log verification event
        self.log_custody_event(
            file_id,
            CustodyEventType::Verified,
            actor,
            Some(&format!("Integrity check: {}", if is_valid { "PASSED" } else { "FAILED" })),
            None,
        ).await?;

        Ok(is_valid)
    }

    /// Archive a file
    pub async fn archive_file(&self, file_id: &str, actor: &str) -> Result<()> {
        sqlx::query("UPDATE audit_files SET is_archived = 1 WHERE id = ?")
            .bind(file_id)
            .execute(&self.pool)
            .await?;

        self.log_custody_event(
            file_id,
            CustodyEventType::Archived,
            actor,
            Some("File archived"),
            None,
        ).await?;

        Ok(())
    }

    /// Restore an archived file
    pub async fn restore_file(&self, file_id: &str, actor: &str) -> Result<()> {
        sqlx::query("UPDATE audit_files SET is_archived = 0 WHERE id = ?")
            .bind(file_id)
            .execute(&self.pool)
            .await?;

        self.log_custody_event(
            file_id,
            CustodyEventType::Restored,
            actor,
            Some("File restored from archive"),
            None,
        ).await?;

        Ok(())
    }

    /// Log file download
    pub async fn log_download(&self, file_id: &str, actor: &str, ip_address: Option<&str>) -> Result<()> {
        self.log_custody_event(
            file_id,
            CustodyEventType::Downloaded,
            actor,
            None,
            ip_address,
        ).await
    }

    /// Apply retention policies
    pub async fn apply_retention_policies(&self) -> Result<RetentionResult> {
        let now = Utc::now().to_rfc3339();
        let mut result = RetentionResult::default();

        // Get files past retention date
        let rows = sqlx::query_as::<_, AuditFileRow>(
            r#"
            SELECT id, file_type, filename, file_path, file_size, sha256_hash,
                   version, system_id, asset_id, framework, profile_id, scan_id,
                   created_by, created_at, retention_until, is_archived, notes
            FROM audit_files
            WHERE retention_until IS NOT NULL
              AND retention_until < ?
              AND is_archived = 0
            "#
        )
        .bind(&now)
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let file: AuditFile = row.into();

            // Archive the file
            self.archive_file(&file.id, "system").await?;
            result.archived += 1;
        }

        Ok(result)
    }

    // Private helper methods

    async fn insert_audit_file(&self, file: &AuditFile) -> Result<()> {
        let file_type = file.file_type.to_string();
        let created_at = file.created_at.to_rfc3339();
        let retention_until = file.retention_until.map(|d| d.to_rfc3339());

        sqlx::query(
            r#"
            INSERT INTO audit_files (
                id, file_type, filename, file_path, file_size, sha256_hash,
                version, system_id, asset_id, framework, profile_id, scan_id,
                created_by, created_at, retention_until, is_archived, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&file.id)
        .bind(&file_type)
        .bind(&file.filename)
        .bind(&file.file_path)
        .bind(file.file_size)
        .bind(&file.sha256_hash)
        .bind(file.version)
        .bind(&file.system_id)
        .bind(&file.asset_id)
        .bind(&file.framework)
        .bind(&file.profile_id)
        .bind(&file.scan_id)
        .bind(&file.created_by)
        .bind(&created_at)
        .bind(&retention_until)
        .bind(file.is_archived)
        .bind(&file.notes)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn insert_version(&self, version: &AuditFileVersion) -> Result<()> {
        let created_at = version.created_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO audit_file_versions (
                id, audit_file_id, version, file_path, file_size, sha256_hash,
                created_by, created_at, change_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&version.id)
        .bind(&version.audit_file_id)
        .bind(version.version)
        .bind(&version.file_path)
        .bind(version.file_size)
        .bind(&version.sha256_hash)
        .bind(&version.created_by)
        .bind(&created_at)
        .bind(&version.change_summary)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn log_custody_event(
        &self,
        file_id: &str,
        event_type: CustodyEventType,
        actor: &str,
        details: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let event_id = Uuid::new_v4().to_string();
        let event_type_str = event_type.to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO audit_custody_events (
                id, audit_file_id, event_type, actor, timestamp, details, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(&event_id)
        .bind(file_id)
        .bind(&event_type_str)
        .bind(actor)
        .bind(&now)
        .bind(details)
        .bind(ip_address)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn calculate_retention_date(
        &self,
        file_type: AuditFileType,
        framework: Option<&str>,
    ) -> Result<Option<DateTime<Utc>>> {
        // Look for specific policy first
        let file_type_str = file_type.to_string();

        let row = if let Some(fw) = framework {
            sqlx::query(
                r#"
                SELECT retention_days
                FROM audit_retention_policies
                WHERE (file_type = ? OR file_type IS NULL)
                  AND (framework = ? OR framework IS NULL)
                ORDER BY
                    CASE WHEN file_type IS NOT NULL AND framework IS NOT NULL THEN 1
                         WHEN file_type IS NOT NULL THEN 2
                         WHEN framework IS NOT NULL THEN 3
                         ELSE 4 END
                LIMIT 1
                "#
            )
            .bind(&file_type_str)
            .bind(fw)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT retention_days
                FROM audit_retention_policies
                WHERE is_default = 1
                LIMIT 1
                "#
            )
            .fetch_optional(&self.pool)
            .await?
        };

        let retention_days = row
            .and_then(|r| r.try_get::<i32, _>("retention_days").ok())
            .unwrap_or(2555); // Default 7 years

        Ok(Some(Utc::now() + Duration::days(retention_days as i64)))
    }
}

/// Metadata for audit file creation
#[derive(Debug, Clone, Default)]
pub struct AuditFileMetadata {
    pub system_id: Option<String>,
    pub asset_id: Option<String>,
    pub framework: Option<String>,
    pub profile_id: Option<String>,
    pub scan_id: Option<String>,
    pub notes: Option<String>,
}

/// Filters for listing audit files
#[derive(Debug, Clone, Default)]
pub struct AuditFileFilters {
    pub file_type: Option<AuditFileType>,
    pub framework: Option<String>,
    pub system_id: Option<String>,
    pub include_archived: bool,
    pub archived_only: bool,
    pub limit: Option<i32>,
}

/// Result of retention policy application
#[derive(Debug, Clone, Default)]
pub struct RetentionResult {
    pub archived: usize,
    pub deleted: usize,
    pub errors: Vec<String>,
}

// Database row types for sqlx

#[derive(Debug, FromRow)]
struct AuditFileRow {
    id: String,
    file_type: String,
    filename: String,
    file_path: String,
    file_size: i64,
    sha256_hash: String,
    version: i32,
    system_id: Option<String>,
    asset_id: Option<String>,
    framework: Option<String>,
    profile_id: Option<String>,
    scan_id: Option<String>,
    created_by: String,
    created_at: String,
    retention_until: Option<String>,
    is_archived: bool,
    notes: Option<String>,
}

impl From<AuditFileRow> for AuditFile {
    fn from(row: AuditFileRow) -> Self {
        let file_type = match row.file_type.as_str() {
            "ckl" => AuditFileType::Ckl,
            "arf" => AuditFileType::Arf,
            "xccdf" => AuditFileType::Xccdf,
            "oval" => AuditFileType::Oval,
            _ => AuditFileType::Ckl,
        };

        let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let retention_until = row.retention_until.and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|d| d.with_timezone(&Utc))
                .ok()
        });

        AuditFile {
            id: row.id,
            file_type,
            filename: row.filename,
            file_path: row.file_path,
            file_size: row.file_size,
            sha256_hash: row.sha256_hash,
            version: row.version,
            system_id: row.system_id,
            asset_id: row.asset_id,
            framework: row.framework,
            profile_id: row.profile_id,
            scan_id: row.scan_id,
            created_by: row.created_by,
            created_at,
            retention_until,
            is_archived: row.is_archived,
            notes: row.notes,
        }
    }
}

#[derive(Debug, FromRow)]
struct AuditFileVersionRow {
    id: String,
    audit_file_id: String,
    version: i32,
    file_path: String,
    file_size: i64,
    sha256_hash: String,
    created_by: String,
    created_at: String,
    change_summary: Option<String>,
}

impl From<AuditFileVersionRow> for AuditFileVersion {
    fn from(row: AuditFileVersionRow) -> Self {
        let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        AuditFileVersion {
            id: row.id,
            audit_file_id: row.audit_file_id,
            version: row.version,
            file_path: row.file_path,
            file_size: row.file_size,
            sha256_hash: row.sha256_hash,
            created_by: row.created_by,
            created_at,
            change_summary: row.change_summary,
        }
    }
}

#[derive(Debug, FromRow)]
struct CustodyEventRow {
    id: String,
    audit_file_id: String,
    event_type: String,
    actor: String,
    timestamp: String,
    details: Option<String>,
    ip_address: Option<String>,
}

impl From<CustodyEventRow> for CustodyEvent {
    fn from(row: CustodyEventRow) -> Self {
        let event_type = match row.event_type.as_str() {
            "created" => CustodyEventType::Created,
            "viewed" => CustodyEventType::Viewed,
            "downloaded" => CustodyEventType::Downloaded,
            "modified" => CustodyEventType::Modified,
            "archived" => CustodyEventType::Archived,
            "restored" => CustodyEventType::Restored,
            "deleted" => CustodyEventType::Deleted,
            "exported" => CustodyEventType::Exported,
            "imported" => CustodyEventType::Imported,
            "verified" => CustodyEventType::Verified,
            _ => CustodyEventType::Viewed,
        };

        let timestamp = chrono::DateTime::parse_from_rfc3339(&row.timestamp)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        CustodyEvent {
            id: row.id,
            audit_file_id: row.audit_file_id,
            event_type,
            actor: row.actor,
            timestamp,
            details: row.details,
            ip_address: row.ip_address,
        }
    }
}
