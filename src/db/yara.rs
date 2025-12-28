//! YARA Scanner Database Models
//!
//! Database operations for YARA rules and scan results

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// Status of a YARA scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for YaraScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            YaraScanStatus::Pending => write!(f, "pending"),
            YaraScanStatus::Running => write!(f, "running"),
            YaraScanStatus::Completed => write!(f, "completed"),
            YaraScanStatus::Failed => write!(f, "failed"),
            YaraScanStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl From<&str> for YaraScanStatus {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "running" => YaraScanStatus::Running,
            "completed" => YaraScanStatus::Completed,
            "failed" => YaraScanStatus::Failed,
            "cancelled" => YaraScanStatus::Cancelled,
            _ => YaraScanStatus::Pending,
        }
    }
}

/// A stored YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredYaraRule {
    pub id: String,
    pub name: String,
    pub rule_text: String,
    pub metadata: String,  // JSON
    pub is_builtin: bool,
    pub user_id: Option<String>,
    pub category: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A YARA scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScan {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub target_path: String,
    pub target_type: String,  // "file", "directory", "bytes"
    pub recursive: bool,
    pub status: YaraScanStatus,
    pub rules_used: String,  // JSON array of rule IDs
    pub matches_count: u32,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A YARA match record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchRecord {
    pub id: String,
    pub scan_id: String,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub file_path: Option<String>,
    pub matched_strings: String,  // JSON
    pub metadata: String,  // JSON
    pub tags: String,  // JSON array
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// YARA Rules CRUD
// ============================================================================

/// Create a new YARA rule
pub async fn create_yara_rule(
    pool: &SqlitePool,
    name: &str,
    rule_text: &str,
    metadata: &str,
    is_builtin: bool,
    user_id: Option<&str>,
    category: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_rules (id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(name)
    .bind(rule_text)
    .bind(metadata)
    .bind(is_builtin)
    .bind(user_id)
    .bind(category)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a YARA rule by ID
pub async fn get_yara_rule(pool: &SqlitePool, id: &str) -> Result<Option<StoredYaraRule>> {
    let row = sqlx::query_as::<_, YaraRuleRow>(
        r#"
        SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
        FROM yara_rules
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_rule()?)),
        None => Ok(None),
    }
}

/// Get a YARA rule by name (optionally scoped to a user)
pub async fn get_yara_rule_by_name(pool: &SqlitePool, name: &str, user_id: Option<&str>) -> Result<Option<StoredYaraRule>> {
    let row = if let Some(uid) = user_id {
        sqlx::query_as::<_, YaraRuleRow>(
            r#"
            SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
            FROM yara_rules
            WHERE name = ? AND (user_id = ? OR user_id IS NULL OR is_builtin = 1)
            "#,
        )
        .bind(name)
        .bind(uid)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as::<_, YaraRuleRow>(
            r#"
            SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
            FROM yara_rules
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(pool)
        .await?
    };

    match row {
        Some(r) => Ok(Some(r.into_rule()?)),
        None => Ok(None),
    }
}

/// Delete a YARA rule by name (scoped to a user)
pub async fn delete_yara_rule_by_name(pool: &SqlitePool, name: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query(
        "DELETE FROM yara_rules WHERE name = ? AND user_id = ? AND is_builtin = 0",
    )
    .bind(name)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// List all YARA rules
pub async fn list_yara_rules(
    pool: &SqlitePool,
    include_builtin: bool,
    user_id: Option<&str>,
    category: Option<&str>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<StoredYaraRule>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let query = if include_builtin {
        if let Some(cat) = category {
            sqlx::query_as::<_, YaraRuleRow>(
                r#"
                SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
                FROM yara_rules
                WHERE (is_builtin = 1 OR user_id = ?) AND category = ?
                ORDER BY is_builtin DESC, name ASC
                LIMIT ? OFFSET ?
                "#,
            )
            .bind(user_id)
            .bind(cat)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query_as::<_, YaraRuleRow>(
                r#"
                SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
                FROM yara_rules
                WHERE is_builtin = 1 OR user_id = ?
                ORDER BY is_builtin DESC, name ASC
                LIMIT ? OFFSET ?
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?
        }
    } else {
        sqlx::query_as::<_, YaraRuleRow>(
            r#"
            SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
            FROM yara_rules
            WHERE user_id = ?
            ORDER BY name ASC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    query.into_iter().map(|r| r.into_rule()).collect()
}

/// Get user's custom YARA rules
pub async fn get_user_yara_rules(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<StoredYaraRule>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, YaraRuleRow>(
        r#"
        SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
        FROM yara_rules
        WHERE user_id = ? AND is_builtin = 0
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_rule()).collect()
}

/// Get all builtin YARA rules
pub async fn get_builtin_yara_rules(pool: &SqlitePool) -> Result<Vec<StoredYaraRule>> {
    let rows = sqlx::query_as::<_, YaraRuleRow>(
        r#"
        SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
        FROM yara_rules
        WHERE is_builtin = 1 AND enabled = 1
        ORDER BY category, name
        "#,
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_rule()).collect()
}

/// Get enabled YARA rules for scanning
pub async fn get_enabled_yara_rules(
    pool: &SqlitePool,
    user_id: Option<&str>,
) -> Result<Vec<StoredYaraRule>> {
    let rows = sqlx::query_as::<_, YaraRuleRow>(
        r#"
        SELECT id, name, rule_text, metadata, is_builtin, user_id, category, enabled, created_at, updated_at
        FROM yara_rules
        WHERE enabled = 1 AND (is_builtin = 1 OR user_id = ?)
        ORDER BY is_builtin DESC, name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_rule()).collect()
}

/// Update a YARA rule
pub async fn update_yara_rule(
    pool: &SqlitePool,
    id: &str,
    name: Option<&str>,
    rule_text: Option<&str>,
    metadata: Option<&str>,
    category: Option<&str>,
    enabled: Option<bool>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    // Build dynamic update query
    let mut updates = vec!["updated_at = ?"];
    let mut has_name = false;
    let mut has_rule_text = false;
    let mut has_metadata = false;
    let mut has_category = false;
    let mut has_enabled = false;

    if name.is_some() {
        updates.push("name = ?");
        has_name = true;
    }
    if rule_text.is_some() {
        updates.push("rule_text = ?");
        has_rule_text = true;
    }
    if metadata.is_some() {
        updates.push("metadata = ?");
        has_metadata = true;
    }
    if category.is_some() {
        updates.push("category = ?");
        has_category = true;
    }
    if enabled.is_some() {
        updates.push("enabled = ?");
        has_enabled = true;
    }

    let query = format!(
        "UPDATE yara_rules SET {} WHERE id = ? AND is_builtin = 0",
        updates.join(", ")
    );

    let mut q = sqlx::query(&query).bind(&now);

    if has_name {
        q = q.bind(name);
    }
    if has_rule_text {
        q = q.bind(rule_text);
    }
    if has_metadata {
        q = q.bind(metadata);
    }
    if has_category {
        q = q.bind(category);
    }
    if has_enabled {
        q = q.bind(enabled);
    }

    q = q.bind(id);

    let result = q.execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// Delete a YARA rule (only custom rules)
pub async fn delete_yara_rule(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM yara_rules WHERE id = ? AND is_builtin = 0")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Count YARA rules
pub async fn count_yara_rules(
    pool: &SqlitePool,
    user_id: Option<&str>,
    include_builtin: bool,
) -> Result<i64> {
    let row: (i64,) = if include_builtin {
        sqlx::query_as("SELECT COUNT(*) FROM yara_rules WHERE is_builtin = 1 OR user_id = ?")
            .bind(user_id)
            .fetch_one(pool)
            .await?
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM yara_rules WHERE user_id = ? AND is_builtin = 0")
            .bind(user_id)
            .fetch_one(pool)
            .await?
    };
    Ok(row.0)
}

// ============================================================================
// YARA Scans CRUD
// ============================================================================

/// Create a new YARA scan
pub async fn create_yara_scan(
    pool: &SqlitePool,
    user_id: &str,
    name: Option<&str>,
    target_path: &str,
    target_type: &str,
    recursive: bool,
    rules_used: &[String],
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let rules_json = serde_json::to_string(rules_used)?;

    sqlx::query(
        r#"
        INSERT INTO yara_scans (id, user_id, name, target_path, target_type, recursive, status, rules_used,
                                matches_count, files_scanned, bytes_scanned, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 0, 0, 0, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(target_path)
    .bind(target_type)
    .bind(recursive)
    .bind(&rules_json)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a YARA scan by ID
pub async fn get_yara_scan(pool: &SqlitePool, id: &str) -> Result<Option<YaraScan>> {
    let row = sqlx::query_as::<_, YaraScanRow>(
        r#"
        SELECT id, user_id, name, target_path, target_type, recursive, status, rules_used,
               matches_count, files_scanned, bytes_scanned, error_message,
               created_at, started_at, completed_at
        FROM yara_scans
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_scan()?)),
        None => Ok(None),
    }
}

/// Get user's YARA scans
pub async fn get_user_yara_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<YaraScan>> {
    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, YaraScanRow>(
        r#"
        SELECT id, user_id, name, target_path, target_type, recursive, status, rules_used,
               matches_count, files_scanned, bytes_scanned, error_message,
               created_at, started_at, completed_at
        FROM yara_scans
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_scan()).collect()
}

/// Update YARA scan status
pub async fn update_yara_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: YaraScanStatus,
    error_message: Option<&str>,
) -> Result<()> {
    let status_str = status.to_string();
    let now = Utc::now().to_rfc3339();

    match status {
        YaraScanStatus::Running => {
            sqlx::query(
                "UPDATE yara_scans SET status = ?, started_at = ? WHERE id = ?",
            )
            .bind(&status_str)
            .bind(&now)
            .bind(id)
            .execute(pool)
            .await?;
        }
        YaraScanStatus::Completed | YaraScanStatus::Failed | YaraScanStatus::Cancelled => {
            sqlx::query(
                "UPDATE yara_scans SET status = ?, completed_at = ?, error_message = ? WHERE id = ?",
            )
            .bind(&status_str)
            .bind(&now)
            .bind(error_message)
            .bind(id)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query(
                "UPDATE yara_scans SET status = ?, error_message = ? WHERE id = ?",
            )
            .bind(&status_str)
            .bind(error_message)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

/// Update YARA scan statistics
pub async fn update_yara_scan_stats(
    pool: &SqlitePool,
    id: &str,
    matches_count: u32,
    files_scanned: u64,
    bytes_scanned: u64,
) -> Result<()> {
    sqlx::query(
        "UPDATE yara_scans SET matches_count = ?, files_scanned = ?, bytes_scanned = ? WHERE id = ?",
    )
    .bind(matches_count as i64)
    .bind(files_scanned as i64)
    .bind(bytes_scanned as i64)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a YARA scan
pub async fn delete_yara_scan(pool: &SqlitePool, id: &str) -> Result<bool> {
    // Delete matches first
    sqlx::query("DELETE FROM yara_matches WHERE scan_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    // Delete scan
    let result = sqlx::query("DELETE FROM yara_scans WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Count user's YARA scans
pub async fn count_user_yara_scans(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM yara_scans WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Update a YARA scan with an error message
pub async fn update_yara_scan_error(pool: &SqlitePool, id: &str, error: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE yara_scans
        SET status = 'error', error_message = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(error)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Complete a YARA scan with results
pub async fn complete_yara_scan(
    pool: &SqlitePool,
    id: &str,
    matches_count: i64,
    files_scanned: i64,
    bytes_scanned: i64,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE yara_scans
        SET status = 'completed', matches_count = ?, files_scanned = ?, bytes_scanned = ?, completed_at = ?
        WHERE id = ?
        "#,
    )
    .bind(matches_count)
    .bind(files_scanned)
    .bind(bytes_scanned)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Create a YARA match (simplified version for bulk scans)
pub async fn create_yara_match(
    pool: &SqlitePool,
    id: &str,
    scan_id: &str,
    rule_name: &str,
    file_path: Option<&str>,
    matched_strings: &str,
    metadata: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_matches (id, scan_id, rule_name, rule_id, file_path, matched_strings, metadata, tags, created_at)
        VALUES (?, ?, ?, NULL, ?, ?, ?, '[]', ?)
        "#,
    )
    .bind(id)
    .bind(scan_id)
    .bind(rule_name)
    .bind(file_path)
    .bind(matched_strings)
    .bind(metadata)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// YARA Matches CRUD
// ============================================================================

/// Save a YARA match
pub async fn save_yara_match(
    pool: &SqlitePool,
    scan_id: &str,
    rule_name: &str,
    rule_id: Option<&str>,
    file_path: Option<&str>,
    matched_strings: &str,  // JSON
    metadata: &str,  // JSON
    tags: &str,  // JSON
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_matches (id, scan_id, rule_name, rule_id, file_path, matched_strings, metadata, tags, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(rule_name)
    .bind(rule_id)
    .bind(file_path)
    .bind(matched_strings)
    .bind(metadata)
    .bind(tags)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Save multiple YARA matches
pub async fn save_yara_matches(
    pool: &SqlitePool,
    scan_id: &str,
    matches: &[crate::scanner::yara::YaraMatch],
) -> Result<()> {
    for m in matches {
        let matched_strings_json = serde_json::to_string(&m.matched_strings)?;
        let metadata_json = serde_json::to_string(&m.metadata)?;
        let tags_json = serde_json::to_string(&m.tags)?;

        save_yara_match(
            pool,
            scan_id,
            &m.rule_name,
            None,
            m.file_path.as_deref(),
            &matched_strings_json,
            &metadata_json,
            &tags_json,
        ).await?;
    }

    Ok(())
}

/// Get matches for a scan
pub async fn get_yara_matches(
    pool: &SqlitePool,
    scan_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<YaraMatchRecord>> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    let rows = sqlx::query_as::<_, YaraMatchRow>(
        r#"
        SELECT id, scan_id, rule_name, rule_id, file_path, matched_strings, metadata, tags, created_at
        FROM yara_matches
        WHERE scan_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(scan_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_match()).collect()
}

/// Get a specific match
pub async fn get_yara_match(pool: &SqlitePool, id: &str) -> Result<Option<YaraMatchRecord>> {
    let row = sqlx::query_as::<_, YaraMatchRow>(
        r#"
        SELECT id, scan_id, rule_name, rule_id, file_path, matched_strings, metadata, tags, created_at
        FROM yara_matches
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_match()?)),
        None => Ok(None),
    }
}

/// Count matches for a scan
pub async fn count_yara_matches(pool: &SqlitePool, scan_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM yara_matches WHERE scan_id = ?")
        .bind(scan_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Get matches grouped by rule
pub async fn get_matches_by_rule(pool: &SqlitePool, scan_id: &str) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT rule_name, COUNT(*) as count
        FROM yara_matches
        WHERE scan_id = ?
        GROUP BY rule_name
        ORDER BY count DESC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// ============================================================================
// Row Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct YaraRuleRow {
    id: String,
    name: String,
    rule_text: String,
    metadata: String,
    is_builtin: bool,
    user_id: Option<String>,
    category: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
}

impl YaraRuleRow {
    fn into_rule(self) -> Result<StoredYaraRule> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(StoredYaraRule {
            id: self.id,
            name: self.name,
            rule_text: self.rule_text,
            metadata: self.metadata,
            is_builtin: self.is_builtin,
            user_id: self.user_id,
            category: self.category,
            enabled: self.enabled,
            created_at,
            updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct YaraScanRow {
    id: String,
    user_id: String,
    name: Option<String>,
    target_path: String,
    target_type: String,
    recursive: bool,
    status: String,
    rules_used: String,
    matches_count: i64,
    files_scanned: i64,
    bytes_scanned: i64,
    error_message: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl YaraScanRow {
    fn into_scan(self) -> Result<YaraScan> {
        let status = YaraScanStatus::from(self.status.as_str());

        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let started_at = self.started_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        let completed_at = self.completed_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        Ok(YaraScan {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            target_path: self.target_path,
            target_type: self.target_type,
            recursive: self.recursive,
            status,
            rules_used: self.rules_used,
            matches_count: self.matches_count as u32,
            files_scanned: self.files_scanned as u64,
            bytes_scanned: self.bytes_scanned as u64,
            error_message: self.error_message,
            created_at,
            started_at,
            completed_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct YaraMatchRow {
    id: String,
    scan_id: String,
    rule_name: String,
    rule_id: Option<String>,
    file_path: Option<String>,
    matched_strings: String,
    metadata: String,
    tags: String,
    created_at: String,
}

impl YaraMatchRow {
    fn into_match(self) -> Result<YaraMatchRecord> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(YaraMatchRecord {
            id: self.id,
            scan_id: self.scan_id,
            rule_name: self.rule_name,
            rule_id: self.rule_id,
            file_path: self.file_path,
            matched_strings: self.matched_strings,
            metadata: self.metadata,
            tags: self.tags,
            created_at,
        })
    }
}

// ============================================================================
// Migration
// ============================================================================

/// Initialize YARA tables
pub async fn create_yara_tables(pool: &SqlitePool) -> Result<()> {
    // YARA rules table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            rule_text TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            is_builtin BOOLEAN NOT NULL DEFAULT 0,
            user_id TEXT,
            category TEXT,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rules_user_id ON yara_rules(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rules_is_builtin ON yara_rules(is_builtin)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rules_category ON yara_rules(category)")
        .execute(pool)
        .await?;

    // YARA scans table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT,
            target_path TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT 'file',
            recursive BOOLEAN NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            rules_used TEXT NOT NULL DEFAULT '[]',
            matches_count INTEGER DEFAULT 0,
            files_scanned INTEGER DEFAULT 0,
            bytes_scanned INTEGER DEFAULT 0,
            error_message TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_scans_user_id ON yara_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_scans_status ON yara_scans(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_scans_created_at ON yara_scans(created_at)")
        .execute(pool)
        .await?;

    // YARA matches table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_matches (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            rule_id TEXT,
            file_path TEXT,
            matched_strings TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            tags TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES yara_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (rule_id) REFERENCES yara_rules(id) ON DELETE SET NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_matches_scan_id ON yara_matches(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_matches_rule_name ON yara_matches(rule_name)")
        .execute(pool)
        .await?;

    Ok(())
}

/// Seed builtin YARA rules
pub async fn seed_builtin_yara_rules(pool: &SqlitePool) -> Result<()> {
    use crate::scanner::yara::rules::get_builtin_rules;

    let rules = get_builtin_rules();

    for rule in rules {
        // Check if rule already exists
        let existing = get_yara_rule_by_name(pool, &rule.name, None).await?;
        if existing.is_some() {
            continue;
        }

        let metadata = serde_json::to_string(&rule.metadata)?;
        let category = if rule.tags.contains(&"malware".to_string()) {
            Some("Malware")
        } else if rule.tags.contains(&"webshell".to_string()) {
            Some("Webshell")
        } else if rule.tags.contains(&"cryptominer".to_string()) {
            Some("Cryptominer")
        } else if rule.tags.contains(&"rat".to_string()) || rule.tags.contains(&"backdoor".to_string()) {
            Some("RAT")
        } else if rule.tags.contains(&"ransomware".to_string()) {
            Some("Ransomware")
        } else if rule.tags.contains(&"packer".to_string()) {
            Some("Packer")
        } else if rule.tags.contains(&"pe".to_string()) {
            Some("Suspicious PE")
        } else if rule.tags.contains(&"rootkit".to_string()) {
            Some("Rootkit")
        } else {
            None
        };

        let rule_text = rule.to_yara_text();

        create_yara_rule(
            pool,
            &rule.name,
            &rule_text,
            &metadata,
            true,
            None,
            category,
        ).await?;
    }

    Ok(())
}
