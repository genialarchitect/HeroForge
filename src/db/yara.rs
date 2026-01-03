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
// Sprint 1 P2: New Types
// ============================================================================

/// Detailed per-file scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraScanResult {
    pub id: String,
    pub scan_id: String,
    pub file_path: String,
    pub file_size: i64,
    pub file_hash_md5: Option<String>,
    pub file_hash_sha256: Option<String>,
    pub file_type: Option<String>,
    pub scan_time_ms: i64,
    pub matches_count: i32,
    pub matches_json: String,
    pub error_message: Option<String>,
    pub scanned_at: DateTime<Utc>,
}

/// Community rule source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSource {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub source_type: String,
    pub url: String,
    pub branch: Option<String>,
    pub api_key_encrypted: Option<String>,
    pub is_enabled: bool,
    pub auto_update: bool,
    pub update_interval_hours: i32,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub rules_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Rule effectiveness metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleEffectiveness {
    pub id: String,
    pub rule_id: String,
    pub date: String,
    pub total_scans: i32,
    pub total_matches: i32,
    pub true_positives: i32,
    pub false_positives: i32,
    pub avg_scan_time_ms: f64,
    pub max_scan_time_ms: f64,
    pub effectiveness_score: f64,
    pub updated_at: DateTime<Utc>,
}

/// File monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraFileMonitor {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub watch_paths: String,  // JSON array
    pub exclude_patterns: String,  // JSON array
    pub rule_ids: String,  // JSON array
    pub recursive: bool,
    pub follow_symlinks: bool,
    pub max_file_size_mb: i32,
    pub debounce_ms: i32,
    pub is_active: bool,
    pub status: String,
    pub last_event_at: Option<DateTime<Utc>>,
    pub events_count: i32,
    pub matches_count: i32,
    pub errors_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Monitor alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMonitorAlert {
    pub id: String,
    pub monitor_id: String,
    pub event_type: String,
    pub file_path: String,
    pub file_size: Option<i64>,
    pub file_hash: Option<String>,
    pub matched_rules: String,  // JSON array
    pub severity: String,
    pub is_acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Memory scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMemoryScan {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub scan_type: String,
    pub source_path: Option<String>,
    pub process_id: Option<i32>,
    pub process_name: Option<String>,
    pub dump_size_bytes: Option<i64>,
    pub status: String,
    pub rules_used: String,
    pub matches_count: i32,
    pub regions_scanned: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Memory scan match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMemoryMatch {
    pub id: String,
    pub scan_id: String,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub region_address: Option<i64>,
    pub region_size: Option<i64>,
    pub region_protection: Option<String>,
    pub matched_strings: String,
    pub metadata: String,
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
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let rules_json = serde_json::to_string(rules_used)?;

    sqlx::query(
        r#"
        INSERT INTO yara_scans (id, user_id, name, target_path, target_type, recursive, status, rules_used,
                                matches_count, files_scanned, bytes_scanned, created_at, customer_id, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 0, 0, 0, ?, ?, ?)
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
    .bind(customer_id)
    .bind(engagement_id)
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
// Sprint 1 P2: Rule Source CRUD
// ============================================================================

/// Create a new rule source
pub async fn create_yara_rule_source(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    source_type: &str,
    url: &str,
    description: Option<&str>,
    branch: Option<&str>,
    auto_update: bool,
    update_interval_hours: i32,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_rule_sources (id, user_id, name, description, source_type, url, branch,
                                       is_enabled, auto_update, update_interval_hours, rules_count,
                                       created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(source_type)
    .bind(url)
    .bind(branch)
    .bind(auto_update)
    .bind(update_interval_hours)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a rule source by ID
pub async fn get_yara_rule_source(pool: &SqlitePool, id: &str) -> Result<Option<YaraRuleSource>> {
    let row = sqlx::query_as::<_, YaraRuleSourceRow>(
        r#"
        SELECT id, user_id, name, description, source_type, url, branch, api_key_encrypted,
               is_enabled, auto_update, update_interval_hours, last_sync_at, last_sync_status,
               last_sync_error, rules_count, created_at, updated_at
        FROM yara_rule_sources WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_source()?)),
        None => Ok(None),
    }
}

/// List rule sources for a user
pub async fn list_yara_rule_sources(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<YaraRuleSource>> {
    let rows = sqlx::query_as::<_, YaraRuleSourceRow>(
        r#"
        SELECT id, user_id, name, description, source_type, url, branch, api_key_encrypted,
               is_enabled, auto_update, update_interval_hours, last_sync_at, last_sync_status,
               last_sync_error, rules_count, created_at, updated_at
        FROM yara_rule_sources WHERE user_id = ?
        ORDER BY name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_source()).collect()
}

/// Update rule source sync status
pub async fn update_yara_rule_source_sync(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error: Option<&str>,
    rules_count: i32,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"
        UPDATE yara_rule_sources
        SET last_sync_at = ?, last_sync_status = ?, last_sync_error = ?, rules_count = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&now)
    .bind(status)
    .bind(error)
    .bind(rules_count)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete a rule source
pub async fn delete_yara_rule_source(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM yara_rule_sources WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

#[derive(sqlx::FromRow)]
struct YaraRuleSourceRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    source_type: String,
    url: String,
    branch: Option<String>,
    api_key_encrypted: Option<String>,
    is_enabled: bool,
    auto_update: bool,
    update_interval_hours: i32,
    last_sync_at: Option<String>,
    last_sync_status: Option<String>,
    last_sync_error: Option<String>,
    rules_count: i32,
    created_at: String,
    updated_at: String,
}

impl YaraRuleSourceRow {
    fn into_source(self) -> Result<YaraRuleSource> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let last_sync_at = self.last_sync_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        Ok(YaraRuleSource {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            description: self.description,
            source_type: self.source_type,
            url: self.url,
            branch: self.branch,
            api_key_encrypted: self.api_key_encrypted,
            is_enabled: self.is_enabled,
            auto_update: self.auto_update,
            update_interval_hours: self.update_interval_hours,
            last_sync_at,
            last_sync_status: self.last_sync_status,
            last_sync_error: self.last_sync_error,
            rules_count: self.rules_count,
            created_at,
            updated_at,
        })
    }
}

// ============================================================================
// Sprint 1 P2: Rule Effectiveness CRUD
// ============================================================================

/// Record or update rule effectiveness for today
pub async fn record_yara_rule_effectiveness(
    pool: &SqlitePool,
    rule_id: &str,
    scan_time_ms: f64,
    matched: bool,
    is_true_positive: Option<bool>,
) -> Result<()> {
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let now = Utc::now().to_rfc3339();

    // Try to update existing record
    let result = sqlx::query(
        r#"
        UPDATE yara_rule_effectiveness
        SET total_scans = total_scans + 1,
            total_matches = total_matches + ?,
            true_positives = true_positives + ?,
            false_positives = false_positives + ?,
            avg_scan_time_ms = (avg_scan_time_ms * total_scans + ?) / (total_scans + 1),
            max_scan_time_ms = MAX(max_scan_time_ms, ?),
            effectiveness_score = CASE
                WHEN (true_positives + false_positives) > 0
                THEN CAST(true_positives AS REAL) / (true_positives + false_positives)
                ELSE 0.5
            END,
            updated_at = ?
        WHERE rule_id = ? AND date = ?
        "#,
    )
    .bind(if matched { 1 } else { 0 })
    .bind(if is_true_positive == Some(true) { 1 } else { 0 })
    .bind(if is_true_positive == Some(false) { 1 } else { 0 })
    .bind(scan_time_ms)
    .bind(scan_time_ms)
    .bind(&now)
    .bind(rule_id)
    .bind(&today)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        // Insert new record
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO yara_rule_effectiveness (id, rule_id, date, total_scans, total_matches,
                                                 true_positives, false_positives, avg_scan_time_ms,
                                                 max_scan_time_ms, effectiveness_score, updated_at)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 0.5, ?)
            "#,
        )
        .bind(&id)
        .bind(rule_id)
        .bind(&today)
        .bind(if matched { 1 } else { 0 })
        .bind(if is_true_positive == Some(true) { 1 } else { 0 })
        .bind(if is_true_positive == Some(false) { 1 } else { 0 })
        .bind(scan_time_ms)
        .bind(scan_time_ms)
        .bind(&now)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get rule effectiveness history
pub async fn get_yara_rule_effectiveness_history(
    pool: &SqlitePool,
    rule_id: &str,
    days: i32,
) -> Result<Vec<YaraRuleEffectiveness>> {
    let rows = sqlx::query_as::<_, YaraRuleEffectivenessRow>(
        r#"
        SELECT id, rule_id, date, total_scans, total_matches, true_positives, false_positives,
               avg_scan_time_ms, max_scan_time_ms, effectiveness_score, updated_at
        FROM yara_rule_effectiveness
        WHERE rule_id = ? AND date >= date('now', '-' || ? || ' days')
        ORDER BY date DESC
        "#,
    )
    .bind(rule_id)
    .bind(days)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_effectiveness()).collect()
}

/// Mark a match as true/false positive
pub async fn mark_yara_match_verification(
    pool: &SqlitePool,
    rule_id: &str,
    is_true_positive: bool,
) -> Result<()> {
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE yara_rule_effectiveness
        SET true_positives = true_positives + ?,
            false_positives = false_positives + ?,
            effectiveness_score = CASE
                WHEN (true_positives + false_positives + 1) > 0
                THEN CAST(true_positives + ?) AS REAL / (true_positives + false_positives + 1)
                ELSE 0.5
            END,
            updated_at = ?
        WHERE rule_id = ? AND date = ?
        "#,
    )
    .bind(if is_true_positive { 1 } else { 0 })
    .bind(if is_true_positive { 0 } else { 1 })
    .bind(if is_true_positive { 1 } else { 0 })
    .bind(&now)
    .bind(rule_id)
    .bind(&today)
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(sqlx::FromRow)]
struct YaraRuleEffectivenessRow {
    id: String,
    rule_id: String,
    date: String,
    total_scans: i32,
    total_matches: i32,
    true_positives: i32,
    false_positives: i32,
    avg_scan_time_ms: f64,
    max_scan_time_ms: f64,
    effectiveness_score: f64,
    updated_at: String,
}

impl YaraRuleEffectivenessRow {
    fn into_effectiveness(self) -> Result<YaraRuleEffectiveness> {
        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(YaraRuleEffectiveness {
            id: self.id,
            rule_id: self.rule_id,
            date: self.date,
            total_scans: self.total_scans,
            total_matches: self.total_matches,
            true_positives: self.true_positives,
            false_positives: self.false_positives,
            avg_scan_time_ms: self.avg_scan_time_ms,
            max_scan_time_ms: self.max_scan_time_ms,
            effectiveness_score: self.effectiveness_score,
            updated_at,
        })
    }
}

// ============================================================================
// Sprint 1 P2: File Monitor CRUD
// ============================================================================

/// Create a file monitor
pub async fn create_yara_file_monitor(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    watch_paths: &[String],
    rule_ids: &[String],
    description: Option<&str>,
    exclude_patterns: Option<&[String]>,
    recursive: bool,
    max_file_size_mb: i32,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let watch_paths_json = serde_json::to_string(watch_paths)?;
    let rule_ids_json = serde_json::to_string(rule_ids)?;
    let exclude_json = serde_json::to_string(&exclude_patterns.unwrap_or(&[]))?;

    sqlx::query(
        r#"
        INSERT INTO yara_file_monitors (id, user_id, name, description, watch_paths, exclude_patterns,
                                        rule_ids, recursive, max_file_size_mb, is_active, status,
                                        events_count, matches_count, errors_count, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'stopped', 0, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(&watch_paths_json)
    .bind(&exclude_json)
    .bind(&rule_ids_json)
    .bind(recursive)
    .bind(max_file_size_mb)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a file monitor by ID
pub async fn get_yara_file_monitor(pool: &SqlitePool, id: &str) -> Result<Option<YaraFileMonitor>> {
    let row = sqlx::query_as::<_, YaraFileMonitorRow>(
        r#"
        SELECT id, user_id, name, description, watch_paths, exclude_patterns, rule_ids, recursive,
               follow_symlinks, max_file_size_mb, debounce_ms, is_active, status, last_event_at,
               events_count, matches_count, errors_count, created_at, updated_at
        FROM yara_file_monitors WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.into_monitor()?)),
        None => Ok(None),
    }
}

/// List file monitors for a user
pub async fn list_yara_file_monitors(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<YaraFileMonitor>> {
    let rows = sqlx::query_as::<_, YaraFileMonitorRow>(
        r#"
        SELECT id, user_id, name, description, watch_paths, exclude_patterns, rule_ids, recursive,
               follow_symlinks, max_file_size_mb, debounce_ms, is_active, status, last_event_at,
               events_count, matches_count, errors_count, created_at, updated_at
        FROM yara_file_monitors WHERE user_id = ?
        ORDER BY name
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_monitor()).collect()
}

/// Update monitor status
pub async fn update_yara_file_monitor_status(
    pool: &SqlitePool,
    id: &str,
    is_active: bool,
    status: &str,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        "UPDATE yara_file_monitors SET is_active = ?, status = ?, updated_at = ? WHERE id = ?",
    )
    .bind(is_active)
    .bind(status)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Increment monitor event counts
pub async fn increment_yara_monitor_counts(
    pool: &SqlitePool,
    id: &str,
    events: i32,
    matches: i32,
    errors: i32,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE yara_file_monitors
        SET events_count = events_count + ?, matches_count = matches_count + ?,
            errors_count = errors_count + ?, last_event_at = ?, updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(events)
    .bind(matches)
    .bind(errors)
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a file monitor
pub async fn delete_yara_file_monitor(pool: &SqlitePool, id: &str, user_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM yara_file_monitors WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

#[derive(sqlx::FromRow)]
struct YaraFileMonitorRow {
    id: String,
    user_id: String,
    name: String,
    description: Option<String>,
    watch_paths: String,
    exclude_patterns: String,
    rule_ids: String,
    recursive: bool,
    follow_symlinks: bool,
    max_file_size_mb: i32,
    debounce_ms: i32,
    is_active: bool,
    status: String,
    last_event_at: Option<String>,
    events_count: i32,
    matches_count: i32,
    errors_count: i32,
    created_at: String,
    updated_at: String,
}

impl YaraFileMonitorRow {
    fn into_monitor(self) -> Result<YaraFileMonitor> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let updated_at = DateTime::parse_from_rfc3339(&self.updated_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let last_event_at = self.last_event_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        Ok(YaraFileMonitor {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            description: self.description,
            watch_paths: self.watch_paths,
            exclude_patterns: self.exclude_patterns,
            rule_ids: self.rule_ids,
            recursive: self.recursive,
            follow_symlinks: self.follow_symlinks,
            max_file_size_mb: self.max_file_size_mb,
            debounce_ms: self.debounce_ms,
            is_active: self.is_active,
            status: self.status,
            last_event_at,
            events_count: self.events_count,
            matches_count: self.matches_count,
            errors_count: self.errors_count,
            created_at,
            updated_at,
        })
    }
}

// ============================================================================
// Sprint 1 P2: Monitor Alert CRUD
// ============================================================================

/// Create a monitor alert
pub async fn create_yara_monitor_alert(
    pool: &SqlitePool,
    monitor_id: &str,
    event_type: &str,
    file_path: &str,
    file_size: Option<i64>,
    file_hash: Option<&str>,
    matched_rules: &[String],
    severity: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let matched_rules_json = serde_json::to_string(matched_rules)?;

    sqlx::query(
        r#"
        INSERT INTO yara_monitor_alerts (id, monitor_id, event_type, file_path, file_size,
                                         file_hash, matched_rules, severity, is_acknowledged, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        "#,
    )
    .bind(&id)
    .bind(monitor_id)
    .bind(event_type)
    .bind(file_path)
    .bind(file_size)
    .bind(file_hash)
    .bind(&matched_rules_json)
    .bind(severity)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get monitor alerts
pub async fn get_yara_monitor_alerts(
    pool: &SqlitePool,
    monitor_id: &str,
    limit: i64,
    offset: i64,
    unacknowledged_only: bool,
) -> Result<Vec<YaraMonitorAlert>> {
    let rows = if unacknowledged_only {
        sqlx::query_as::<_, YaraMonitorAlertRow>(
            r#"
            SELECT id, monitor_id, event_type, file_path, file_size, file_hash, matched_rules,
                   severity, is_acknowledged, acknowledged_by, acknowledged_at, notes, created_at
            FROM yara_monitor_alerts
            WHERE monitor_id = ? AND is_acknowledged = 0
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(monitor_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, YaraMonitorAlertRow>(
            r#"
            SELECT id, monitor_id, event_type, file_path, file_size, file_hash, matched_rules,
                   severity, is_acknowledged, acknowledged_by, acknowledged_at, notes, created_at
            FROM yara_monitor_alerts
            WHERE monitor_id = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            "#,
        )
        .bind(monitor_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_alert()).collect()
}

/// Acknowledge an alert
pub async fn acknowledge_yara_monitor_alert(
    pool: &SqlitePool,
    id: &str,
    user_id: &str,
    notes: Option<&str>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query(
        r#"
        UPDATE yara_monitor_alerts
        SET is_acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?, notes = ?
        WHERE id = ?
        "#,
    )
    .bind(user_id)
    .bind(&now)
    .bind(notes)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

#[derive(sqlx::FromRow)]
struct YaraMonitorAlertRow {
    id: String,
    monitor_id: String,
    event_type: String,
    file_path: String,
    file_size: Option<i64>,
    file_hash: Option<String>,
    matched_rules: String,
    severity: String,
    is_acknowledged: bool,
    acknowledged_by: Option<String>,
    acknowledged_at: Option<String>,
    notes: Option<String>,
    created_at: String,
}

impl YaraMonitorAlertRow {
    fn into_alert(self) -> Result<YaraMonitorAlert> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let acknowledged_at = self.acknowledged_at.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        Ok(YaraMonitorAlert {
            id: self.id,
            monitor_id: self.monitor_id,
            event_type: self.event_type,
            file_path: self.file_path,
            file_size: self.file_size,
            file_hash: self.file_hash,
            matched_rules: self.matched_rules,
            severity: self.severity,
            is_acknowledged: self.is_acknowledged,
            acknowledged_by: self.acknowledged_by,
            acknowledged_at,
            notes: self.notes,
            created_at,
        })
    }
}

// ============================================================================
// Sprint 1 P2: Memory Scan CRUD
// ============================================================================

/// Create a memory scan
pub async fn create_yara_memory_scan(
    pool: &SqlitePool,
    user_id: &str,
    name: Option<&str>,
    scan_type: &str,
    source_path: Option<&str>,
    process_id: Option<i32>,
    process_name: Option<&str>,
    rules_used: &[String],
    customer_id: Option<&str>,
    engagement_id: Option<&str>,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let rules_json = serde_json::to_string(rules_used)?;

    sqlx::query(
        r#"
        INSERT INTO yara_memory_scans (id, user_id, name, scan_type, source_path, process_id,
                                       process_name, status, rules_used, matches_count,
                                       regions_scanned, created_at, customer_id, engagement_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, 0, 0, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(scan_type)
    .bind(source_path)
    .bind(process_id)
    .bind(process_name)
    .bind(&rules_json)
    .bind(&now)
    .bind(customer_id)
    .bind(engagement_id)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get a memory scan by ID
pub async fn get_yara_memory_scan(pool: &SqlitePool, id: &str) -> Result<Option<YaraMemoryScan>> {
    let row = sqlx::query_as::<_, YaraMemoryScanRow>(
        r#"
        SELECT id, user_id, name, scan_type, source_path, process_id, process_name, dump_size_bytes,
               status, rules_used, matches_count, regions_scanned, error_message,
               created_at, started_at, completed_at
        FROM yara_memory_scans WHERE id = ?
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

/// List memory scans for a user
pub async fn list_yara_memory_scans(
    pool: &SqlitePool,
    user_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<YaraMemoryScan>> {
    let rows = sqlx::query_as::<_, YaraMemoryScanRow>(
        r#"
        SELECT id, user_id, name, scan_type, source_path, process_id, process_name, dump_size_bytes,
               status, rules_used, matches_count, regions_scanned, error_message,
               created_at, started_at, completed_at
        FROM yara_memory_scans WHERE user_id = ?
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

/// Update memory scan status
pub async fn update_yara_memory_scan_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    matches_count: Option<i32>,
    regions_scanned: Option<i32>,
    dump_size_bytes: Option<i64>,
    error_message: Option<&str>,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();

    // Different update based on status
    let result = if status == "running" {
        sqlx::query(
            "UPDATE yara_memory_scans SET status = ?, started_at = ? WHERE id = ?",
        )
        .bind(status)
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?
    } else if status == "completed" || status == "failed" {
        sqlx::query(
            r#"
            UPDATE yara_memory_scans
            SET status = ?, completed_at = ?, matches_count = COALESCE(?, matches_count),
                regions_scanned = COALESCE(?, regions_scanned), dump_size_bytes = COALESCE(?, dump_size_bytes),
                error_message = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(&now)
        .bind(matches_count)
        .bind(regions_scanned)
        .bind(dump_size_bytes)
        .bind(error_message)
        .bind(id)
        .execute(pool)
        .await?
    } else {
        sqlx::query("UPDATE yara_memory_scans SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(pool)
            .await?
    };

    Ok(result.rows_affected() > 0)
}

/// Create a memory scan match
pub async fn create_yara_memory_match(
    pool: &SqlitePool,
    scan_id: &str,
    rule_name: &str,
    rule_id: Option<&str>,
    region_address: Option<i64>,
    region_size: Option<i64>,
    region_protection: Option<&str>,
    matched_strings: &str,
    metadata: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_memory_matches (id, scan_id, rule_name, rule_id, region_address,
                                         region_size, region_protection, matched_strings,
                                         metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(scan_id)
    .bind(rule_name)
    .bind(rule_id)
    .bind(region_address)
    .bind(region_size)
    .bind(region_protection)
    .bind(matched_strings)
    .bind(metadata)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get memory scan matches
pub async fn get_yara_memory_matches(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<YaraMemoryMatch>> {
    let rows = sqlx::query_as::<_, YaraMemoryMatchRow>(
        r#"
        SELECT id, scan_id, rule_name, rule_id, region_address, region_size, region_protection,
               matched_strings, metadata, created_at
        FROM yara_memory_matches WHERE scan_id = ?
        ORDER BY region_address
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_match()).collect()
}

#[derive(sqlx::FromRow)]
struct YaraMemoryScanRow {
    id: String,
    user_id: String,
    name: Option<String>,
    scan_type: String,
    source_path: Option<String>,
    process_id: Option<i32>,
    process_name: Option<String>,
    dump_size_bytes: Option<i64>,
    status: String,
    rules_used: String,
    matches_count: i32,
    regions_scanned: i32,
    error_message: Option<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl YaraMemoryScanRow {
    fn into_scan(self) -> Result<YaraMemoryScan> {
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

        Ok(YaraMemoryScan {
            id: self.id,
            user_id: self.user_id,
            name: self.name,
            scan_type: self.scan_type,
            source_path: self.source_path,
            process_id: self.process_id,
            process_name: self.process_name,
            dump_size_bytes: self.dump_size_bytes,
            status: self.status,
            rules_used: self.rules_used,
            matches_count: self.matches_count,
            regions_scanned: self.regions_scanned,
            error_message: self.error_message,
            created_at,
            started_at,
            completed_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct YaraMemoryMatchRow {
    id: String,
    scan_id: String,
    rule_name: String,
    rule_id: Option<String>,
    region_address: Option<i64>,
    region_size: Option<i64>,
    region_protection: Option<String>,
    matched_strings: String,
    metadata: String,
    created_at: String,
}

impl YaraMemoryMatchRow {
    fn into_match(self) -> Result<YaraMemoryMatch> {
        let created_at = DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(YaraMemoryMatch {
            id: self.id,
            scan_id: self.scan_id,
            rule_name: self.rule_name,
            rule_id: self.rule_id,
            region_address: self.region_address,
            region_size: self.region_size,
            region_protection: self.region_protection,
            matched_strings: self.matched_strings,
            metadata: self.metadata,
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

    // Sprint 1 P2: YARA scan results - detailed per-file results
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_scan_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL DEFAULT 0,
            file_hash_md5 TEXT,
            file_hash_sha256 TEXT,
            file_type TEXT,
            scan_time_ms INTEGER NOT NULL DEFAULT 0,
            matches_count INTEGER NOT NULL DEFAULT 0,
            matches_json TEXT NOT NULL DEFAULT '[]',
            error_message TEXT,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES yara_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_scan_results_scan_id ON yara_scan_results(scan_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_scan_results_file_hash ON yara_scan_results(file_hash_sha256)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: Community rule sources tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_rule_sources (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            source_type TEXT NOT NULL DEFAULT 'github',
            url TEXT NOT NULL,
            branch TEXT DEFAULT 'main',
            api_key_encrypted TEXT,
            is_enabled BOOLEAN NOT NULL DEFAULT 1,
            auto_update BOOLEAN NOT NULL DEFAULT 0,
            update_interval_hours INTEGER DEFAULT 24,
            last_sync_at TEXT,
            last_sync_status TEXT,
            last_sync_error TEXT,
            rules_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rule_sources_user_id ON yara_rule_sources(user_id)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: Rule effectiveness tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_rule_effectiveness (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            date TEXT NOT NULL,
            total_scans INTEGER DEFAULT 0,
            total_matches INTEGER DEFAULT 0,
            true_positives INTEGER DEFAULT 0,
            false_positives INTEGER DEFAULT 0,
            avg_scan_time_ms REAL DEFAULT 0,
            max_scan_time_ms REAL DEFAULT 0,
            effectiveness_score REAL DEFAULT 0,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (rule_id) REFERENCES yara_rules(id) ON DELETE CASCADE,
            UNIQUE(rule_id, date)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rule_effectiveness_rule_id ON yara_rule_effectiveness(rule_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_rule_effectiveness_date ON yara_rule_effectiveness(date)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: Real-time file monitoring configurations
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_file_monitors (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            watch_paths TEXT NOT NULL DEFAULT '[]',
            exclude_patterns TEXT NOT NULL DEFAULT '[]',
            rule_ids TEXT NOT NULL DEFAULT '[]',
            recursive BOOLEAN NOT NULL DEFAULT 1,
            follow_symlinks BOOLEAN NOT NULL DEFAULT 0,
            max_file_size_mb INTEGER DEFAULT 100,
            debounce_ms INTEGER DEFAULT 500,
            is_active BOOLEAN NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'stopped',
            last_event_at TEXT,
            events_count INTEGER DEFAULT 0,
            matches_count INTEGER DEFAULT 0,
            errors_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_file_monitors_user_id ON yara_file_monitors(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_file_monitors_is_active ON yara_file_monitors(is_active)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: File monitor alerts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_monitor_alerts (
            id TEXT PRIMARY KEY,
            monitor_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            file_hash TEXT,
            matched_rules TEXT NOT NULL DEFAULT '[]',
            severity TEXT NOT NULL DEFAULT 'medium',
            is_acknowledged BOOLEAN NOT NULL DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (monitor_id) REFERENCES yara_file_monitors(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_monitor_alerts_monitor_id ON yara_monitor_alerts(monitor_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_monitor_alerts_created_at ON yara_monitor_alerts(created_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_monitor_alerts_is_acknowledged ON yara_monitor_alerts(is_acknowledged)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: Memory scan tracking
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_memory_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT,
            scan_type TEXT NOT NULL DEFAULT 'dump',
            source_path TEXT,
            process_id INTEGER,
            process_name TEXT,
            dump_size_bytes INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            rules_used TEXT NOT NULL DEFAULT '[]',
            matches_count INTEGER DEFAULT 0,
            regions_scanned INTEGER DEFAULT 0,
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_memory_scans_user_id ON yara_memory_scans(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_memory_scans_status ON yara_memory_scans(status)")
        .execute(pool)
        .await?;

    // Sprint 1 P2: Memory scan matches
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS yara_memory_matches (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            rule_id TEXT,
            region_address INTEGER,
            region_size INTEGER,
            region_protection TEXT,
            matched_strings TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES yara_memory_scans(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_yara_memory_matches_scan_id ON yara_memory_matches(scan_id)")
        .execute(pool)
        .await?;

    log::info!("Created Sprint 1 P2 YARA enhancement tables");
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

// ============================================================================
// Sprint 1 P2: Additional Effectiveness Functions
// ============================================================================

/// Effectiveness score with rule info for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEffectivenessWithInfo {
    pub rule_id: String,
    pub rule_name: Option<String>,
    pub score: f64,
    pub total_matches: i64,
    pub true_positives: i64,
    pub false_positives: i64,
    pub pending_verification: i64,
    pub avg_scan_time_ms: f64,
    pub trend: f64,
    pub confidence: f64,
    pub last_match_at: Option<DateTime<Utc>>,
    pub calculated_at: DateTime<Utc>,
}

/// Calculate trend for a rule by comparing recent vs older effectiveness scores
async fn calculate_rule_trend(pool: &SqlitePool, rule_id: &str) -> f64 {
    // Get average score from last 7 days vs previous 7 days
    let recent_avg: Option<(Option<f64>,)> = sqlx::query_as(
        r#"SELECT AVG(effectiveness_score) FROM yara_rule_effectiveness
           WHERE rule_id = ? AND date >= date('now', '-7 days')"#
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let older_avg: Option<(Option<f64>,)> = sqlx::query_as(
        r#"SELECT AVG(effectiveness_score) FROM yara_rule_effectiveness
           WHERE rule_id = ? AND date >= date('now', '-14 days') AND date < date('now', '-7 days')"#
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match (recent_avg, older_avg) {
        (Some((Some(recent),)), Some((Some(older),))) if older > 0.0 => {
            ((recent - older) / older) * 100.0  // Percentage change
        }
        _ => 0.0,
    }
}

/// Get last match timestamp for a rule
async fn get_rule_last_match_at(pool: &SqlitePool, rule_id: &str) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, String>(
        "SELECT MAX(created_at) FROM yara_matches WHERE rule_id = ?"
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc)))
}

/// Get all rule effectiveness scores for a user
pub async fn get_all_yara_rule_effectiveness(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<RuleEffectivenessWithInfo>> {
    let rows = sqlx::query_as::<_, RuleEffectivenessQueryRow>(
        r#"
        SELECT
            e.rule_id,
            r.name as rule_name,
            AVG(e.effectiveness_score) as score,
            SUM(e.total_matches) as total_matches,
            SUM(e.true_positives) as true_positives,
            SUM(e.false_positives) as false_positives,
            SUM(e.total_matches) - SUM(e.true_positives) - SUM(e.false_positives) as pending_verification,
            AVG(e.avg_scan_time_ms) as avg_scan_time_ms,
            MAX(e.updated_at) as calculated_at
        FROM yara_rule_effectiveness e
        LEFT JOIN yara_rules r ON e.rule_id = r.id
        WHERE r.user_id = ? OR r.is_builtin = 1
        GROUP BY e.rule_id
        ORDER BY score DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        let trend = calculate_rule_trend(pool, &r.rule_id).await;
        let last_match_at = get_rule_last_match_at(pool, &r.rule_id).await;

        results.push(RuleEffectivenessWithInfo {
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            score: r.score.unwrap_or(0.5) * 100.0,
            total_matches: r.total_matches.unwrap_or(0),
            true_positives: r.true_positives.unwrap_or(0),
            false_positives: r.false_positives.unwrap_or(0),
            pending_verification: r.pending_verification.unwrap_or(0),
            avg_scan_time_ms: r.avg_scan_time_ms.unwrap_or(0.0),
            trend,
            confidence: if r.total_matches.unwrap_or(0) >= 10 { 0.9 } else { 0.5 },
            last_match_at,
            calculated_at: DateTime::parse_from_rfc3339(&r.calculated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        });
    }

    Ok(results)
}

#[derive(sqlx::FromRow)]
struct RuleEffectivenessQueryRow {
    rule_id: String,
    rule_name: Option<String>,
    score: Option<f64>,
    total_matches: Option<i64>,
    true_positives: Option<i64>,
    false_positives: Option<i64>,
    pending_verification: Option<i64>,
    avg_scan_time_ms: Option<f64>,
    calculated_at: String,
}

/// Get effectiveness for a single rule
pub async fn get_yara_rule_effectiveness(
    pool: &SqlitePool,
    rule_id: &str,
) -> Result<Option<RuleEffectivenessWithInfo>> {
    let row = sqlx::query_as::<_, RuleEffectivenessQueryRow>(
        r#"
        SELECT
            e.rule_id,
            r.name as rule_name,
            AVG(e.effectiveness_score) as score,
            SUM(e.total_matches) as total_matches,
            SUM(e.true_positives) as true_positives,
            SUM(e.false_positives) as false_positives,
            SUM(e.total_matches) - SUM(e.true_positives) - SUM(e.false_positives) as pending_verification,
            AVG(e.avg_scan_time_ms) as avg_scan_time_ms,
            MAX(e.updated_at) as calculated_at
        FROM yara_rule_effectiveness e
        LEFT JOIN yara_rules r ON e.rule_id = r.id
        WHERE e.rule_id = ?
        GROUP BY e.rule_id
        "#,
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let trend = calculate_rule_trend(pool, &r.rule_id).await;
            let last_match_at = get_rule_last_match_at(pool, &r.rule_id).await;

            Ok(Some(RuleEffectivenessWithInfo {
                rule_id: r.rule_id,
                rule_name: r.rule_name,
                score: r.score.unwrap_or(0.5) * 100.0,
                total_matches: r.total_matches.unwrap_or(0),
                true_positives: r.true_positives.unwrap_or(0),
                false_positives: r.false_positives.unwrap_or(0),
                pending_verification: r.pending_verification.unwrap_or(0),
                avg_scan_time_ms: r.avg_scan_time_ms.unwrap_or(0.0),
                trend,
                confidence: if r.total_matches.unwrap_or(0) >= 10 { 0.9 } else { 0.5 },
                last_match_at,
                calculated_at: DateTime::parse_from_rfc3339(&r.calculated_at)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            }))
        }
        None => Ok(None),
    }
}

/// Get rules that need review (low effectiveness or high FP rate)
pub async fn get_yara_rules_needing_review(
    pool: &SqlitePool,
    user_id: &str,
    min_score_threshold: f64,
    max_fp_rate_threshold: f64,
) -> Result<Vec<RuleEffectivenessWithInfo>> {
    let rows = sqlx::query_as::<_, RuleEffectivenessQueryRow>(
        r#"
        SELECT
            e.rule_id,
            r.name as rule_name,
            AVG(e.effectiveness_score) as score,
            SUM(e.total_matches) as total_matches,
            SUM(e.true_positives) as true_positives,
            SUM(e.false_positives) as false_positives,
            SUM(e.total_matches) - SUM(e.true_positives) - SUM(e.false_positives) as pending_verification,
            AVG(e.avg_scan_time_ms) as avg_scan_time_ms,
            MAX(e.updated_at) as calculated_at
        FROM yara_rule_effectiveness e
        LEFT JOIN yara_rules r ON e.rule_id = r.id
        WHERE (r.user_id = ? OR r.is_builtin = 1)
        GROUP BY e.rule_id
        HAVING AVG(e.effectiveness_score) < ?
           OR (SUM(e.false_positives) * 1.0 / NULLIF(SUM(e.true_positives) + SUM(e.false_positives), 0)) > ?
        ORDER BY score ASC
        "#,
    )
    .bind(user_id)
    .bind(min_score_threshold / 100.0)
    .bind(max_fp_rate_threshold)
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(rows.len());
    for r in rows {
        let trend = calculate_rule_trend(pool, &r.rule_id).await;
        let last_match_at = get_rule_last_match_at(pool, &r.rule_id).await;

        results.push(RuleEffectivenessWithInfo {
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            score: r.score.unwrap_or(0.5) * 100.0,
            total_matches: r.total_matches.unwrap_or(0),
            true_positives: r.true_positives.unwrap_or(0),
            false_positives: r.false_positives.unwrap_or(0),
            pending_verification: r.pending_verification.unwrap_or(0),
            avg_scan_time_ms: r.avg_scan_time_ms.unwrap_or(0.0),
            trend,
            confidence: if r.total_matches.unwrap_or(0) >= 10 { 0.9 } else { 0.5 },
            last_match_at,
            calculated_at: DateTime::parse_from_rfc3339(&r.calculated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        });
    }

    Ok(results)
}

/// Effectiveness summary stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessSummary {
    pub total_rules: i64,
    pub rules_with_data: i64,
    pub avg_effectiveness: f64,
    pub total_matches: i64,
    pub total_true_positives: i64,
    pub total_false_positives: i64,
    pub rules_needing_review: i64,
    pub grade_distribution: std::collections::HashMap<String, i64>,
}

/// Get effectiveness summary for a user
pub async fn get_yara_effectiveness_summary(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<EffectivenessSummary> {
    // Get total rules count
    let total_rules: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM yara_rules WHERE user_id = ? OR is_builtin = 1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get effectiveness stats
    let stats = sqlx::query_as::<_, EffectivenessStatsRow>(
        r#"
        SELECT
            COUNT(DISTINCT e.rule_id) as rules_with_data,
            AVG(e.effectiveness_score) as avg_effectiveness,
            SUM(e.total_matches) as total_matches,
            SUM(e.true_positives) as total_true_positives,
            SUM(e.false_positives) as total_false_positives
        FROM yara_rule_effectiveness e
        LEFT JOIN yara_rules r ON e.rule_id = r.id
        WHERE r.user_id = ? OR r.is_builtin = 1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    // Get rules needing review count
    let rules_needing_review: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT e.rule_id)
        FROM yara_rule_effectiveness e
        LEFT JOIN yara_rules r ON e.rule_id = r.id
        WHERE (r.user_id = ? OR r.is_builtin = 1)
        GROUP BY e.rule_id
        HAVING AVG(e.effectiveness_score) < 0.7
           OR (SUM(e.false_positives) * 1.0 / NULLIF(SUM(e.true_positives) + SUM(e.false_positives), 0)) > 0.15
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or((0,));

    // Build grade distribution
    let mut grade_distribution = std::collections::HashMap::new();
    grade_distribution.insert("A".to_string(), 0);
    grade_distribution.insert("B".to_string(), 0);
    grade_distribution.insert("C".to_string(), 0);
    grade_distribution.insert("D".to_string(), 0);
    grade_distribution.insert("F".to_string(), 0);

    Ok(EffectivenessSummary {
        total_rules: total_rules.0,
        rules_with_data: stats.rules_with_data.unwrap_or(0),
        avg_effectiveness: stats.avg_effectiveness.unwrap_or(0.5) * 100.0,
        total_matches: stats.total_matches.unwrap_or(0),
        total_true_positives: stats.total_true_positives.unwrap_or(0),
        total_false_positives: stats.total_false_positives.unwrap_or(0),
        rules_needing_review: rules_needing_review.0,
        grade_distribution,
    })
}

#[derive(sqlx::FromRow)]
struct EffectivenessStatsRow {
    rules_with_data: Option<i64>,
    avg_effectiveness: Option<f64>,
    total_matches: Option<i64>,
    total_true_positives: Option<i64>,
    total_false_positives: Option<i64>,
}

/// Extended mark_yara_match_verification for API usage
pub async fn mark_yara_match_verification_extended(
    pool: &SqlitePool,
    match_id: &str,
    status: &str,
    verified_by: &str,
    notes: Option<&str>,
) -> Result<bool> {
    // For now, we'll just record this as a new effectiveness entry
    // In a full implementation, you'd track individual matches in a separate table
    let now = Utc::now().to_rfc3339();

    // Just log that we verified - in a real implementation this would update a matches table
    log::info!(
        "Match {} verified as {} by {} at {} (notes: {:?})",
        match_id, status, verified_by, now, notes
    );

    Ok(true)
}

// ============================================================================
// Sprint 1 P2: Extended File Monitor Creation
// ============================================================================

/// Create a file monitor with extended options
pub async fn create_yara_file_monitor_extended(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    paths_json: &str,
    recursive: bool,
    include_ext_json: &str,
    exclude_ext_json: &str,
    exclude_paths_json: &str,
    max_file_size: i64,
    rule_ids_json: &str,
    alert_on_create: bool,
    alert_on_modify: bool,
    alert_on_access: bool,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO yara_file_monitors (id, user_id, name, description, watch_paths, exclude_patterns,
                                        rule_ids, recursive, follow_symlinks, max_file_size_mb,
                                        debounce_ms, is_active, status, events_count, matches_count,
                                        errors_count, created_at, updated_at)
        VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 0, ?, 100, 0, 'stopped', 0, 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(paths_json)
    .bind(exclude_paths_json)
    .bind(rule_ids_json)
    .bind(recursive)
    .bind((max_file_size / (1024 * 1024)) as i32) // Convert bytes to MB
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update file monitor status (simplified version for API)
pub async fn update_yara_file_monitor_status_simple(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();
    let is_active = status == "running";

    let result = sqlx::query(
        "UPDATE yara_file_monitors SET is_active = ?, status = ?, updated_at = ? WHERE id = ?",
    )
    .bind(is_active)
    .bind(status)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Delete a file monitor (simplified version for API)
pub async fn delete_yara_file_monitor_simple(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM yara_file_monitors WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get monitor alerts (simplified version for API)
pub async fn get_yara_monitor_alerts_simple(
    pool: &SqlitePool,
    monitor_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<YaraMonitorAlert>> {
    get_yara_monitor_alerts(pool, monitor_id, limit.unwrap_or(50), offset.unwrap_or(0), false).await
}
