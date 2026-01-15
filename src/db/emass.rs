//! Database operations for eMASS (Enterprise Mission Assurance Support Service) integration
//!
//! This module provides CRUD operations for eMASS connection settings, system mappings,
//! sync history, and POA&M cache.

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// eMASS connection settings database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassSettings {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub api_url: String,
    pub auth_type: String, // "pki", "api_key"
    pub certificate_path: Option<String>,
    pub certificate_password_encrypted: Option<String>,
    pub api_key_encrypted: Option<String>,
    pub user_id: Option<String>,
    pub verify_ssl: bool,
    pub timeout_seconds: i32,
    pub is_active: bool,
    pub last_connected_at: Option<String>,
    pub connection_status: String, // "unknown", "connected", "failed"
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// eMASS system mapping database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassSystemMapping {
    pub id: String,
    pub settings_id: String,
    pub emass_system_id: i64,
    pub emass_system_name: String,
    pub emass_system_acronym: Option<String>,
    pub heroforge_customer_id: Option<String>,
    pub heroforge_engagement_id: Option<String>,
    pub sync_controls: bool,
    pub sync_poams: bool,
    pub sync_artifacts: bool,
    pub auto_create_poams: bool,
    pub last_sync_at: Option<String>,
    pub sync_status: String, // "never", "syncing", "success", "failed"
    pub sync_error: Option<String>,
    pub is_active: bool,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// eMASS sync history database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassSyncHistory {
    pub id: String,
    pub mapping_id: String,
    pub sync_type: String, // "controls", "poams", "artifacts", "full"
    pub direction: String, // "push", "pull", "bidirectional"
    pub status: String, // "started", "completed", "failed"
    pub started_at: String,
    pub completed_at: Option<String>,
    pub controls_synced: i32,
    pub poams_created: i32,
    pub poams_updated: i32,
    pub artifacts_uploaded: i32,
    pub errors: i32,
    pub error_message: Option<String>,
    pub sync_details: Option<String>, // JSON with detailed sync info
    pub executed_by: String,
}

/// eMASS POA&M cache database record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassPoamCache {
    pub id: String,
    pub mapping_id: String,
    pub emass_poam_id: i64,
    pub control_acronym: String,
    pub cci: Option<String>,
    pub weakness_description: String,
    pub status: String,
    pub scheduled_completion_date: Option<String>,
    pub actual_completion_date: Option<String>,
    pub milestones: Option<String>, // JSON
    pub resources: Option<String>,
    pub heroforge_finding_id: Option<String>,
    pub last_emass_update: String,
    pub last_sync_at: String,
    pub needs_sync: bool,
    pub local_changes: Option<String>, // JSON of pending changes
}

/// eMASS control status cache
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassControlCache {
    pub id: String,
    pub mapping_id: String,
    pub control_acronym: String,
    pub cci: Option<String>,
    pub compliance_status: String,
    pub implementation_status: String,
    pub responsible_entities: Option<String>,
    pub implementation_narrative: Option<String>,
    pub last_emass_update: String,
    pub last_sync_at: String,
}

/// eMASS artifact record
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EmassArtifact {
    pub id: String,
    pub mapping_id: String,
    pub emass_artifact_id: Option<i64>,
    pub filename: String,
    pub file_type: String,
    pub file_size: i64,
    pub file_hash: String,
    pub local_path: Option<String>,
    pub control_acronyms: Option<String>, // JSON array
    pub poam_ids: Option<String>, // JSON array
    pub upload_status: String, // "pending", "uploading", "uploaded", "failed"
    pub upload_error: Option<String>,
    pub uploaded_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize eMASS database tables
pub async fn init_tables(pool: &SqlitePool) -> Result<()> {
    // eMASS connection settings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_settings (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            api_url TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            certificate_path TEXT,
            certificate_password_encrypted TEXT,
            api_key_encrypted TEXT,
            user_id TEXT,
            verify_ssl INTEGER NOT NULL DEFAULT 1,
            timeout_seconds INTEGER NOT NULL DEFAULT 30,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_connected_at TEXT,
            connection_status TEXT NOT NULL DEFAULT 'unknown',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // eMASS system mappings
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_system_mappings (
            id TEXT PRIMARY KEY,
            settings_id TEXT NOT NULL,
            emass_system_id INTEGER NOT NULL,
            emass_system_name TEXT NOT NULL,
            emass_system_acronym TEXT,
            heroforge_customer_id TEXT,
            heroforge_engagement_id TEXT,
            sync_controls INTEGER NOT NULL DEFAULT 1,
            sync_poams INTEGER NOT NULL DEFAULT 1,
            sync_artifacts INTEGER NOT NULL DEFAULT 1,
            auto_create_poams INTEGER NOT NULL DEFAULT 0,
            last_sync_at TEXT,
            sync_status TEXT NOT NULL DEFAULT 'never',
            sync_error TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (settings_id) REFERENCES emass_settings(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // eMASS sync history
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_sync_history (
            id TEXT PRIMARY KEY,
            mapping_id TEXT NOT NULL,
            sync_type TEXT NOT NULL,
            direction TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            controls_synced INTEGER NOT NULL DEFAULT 0,
            poams_created INTEGER NOT NULL DEFAULT 0,
            poams_updated INTEGER NOT NULL DEFAULT 0,
            artifacts_uploaded INTEGER NOT NULL DEFAULT 0,
            errors INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            sync_details TEXT,
            executed_by TEXT NOT NULL,
            FOREIGN KEY (mapping_id) REFERENCES emass_system_mappings(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // eMASS POA&M cache
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_poam_cache (
            id TEXT PRIMARY KEY,
            mapping_id TEXT NOT NULL,
            emass_poam_id INTEGER NOT NULL,
            control_acronym TEXT NOT NULL,
            cci TEXT,
            weakness_description TEXT NOT NULL,
            status TEXT NOT NULL,
            scheduled_completion_date TEXT,
            actual_completion_date TEXT,
            milestones TEXT,
            resources TEXT,
            heroforge_finding_id TEXT,
            last_emass_update TEXT NOT NULL,
            last_sync_at TEXT NOT NULL,
            needs_sync INTEGER NOT NULL DEFAULT 0,
            local_changes TEXT,
            FOREIGN KEY (mapping_id) REFERENCES emass_system_mappings(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // eMASS control status cache
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_control_cache (
            id TEXT PRIMARY KEY,
            mapping_id TEXT NOT NULL,
            control_acronym TEXT NOT NULL,
            cci TEXT,
            compliance_status TEXT NOT NULL,
            implementation_status TEXT NOT NULL,
            responsible_entities TEXT,
            implementation_narrative TEXT,
            last_emass_update TEXT NOT NULL,
            last_sync_at TEXT NOT NULL,
            FOREIGN KEY (mapping_id) REFERENCES emass_system_mappings(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // eMASS artifacts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS emass_artifacts (
            id TEXT PRIMARY KEY,
            mapping_id TEXT NOT NULL,
            emass_artifact_id INTEGER,
            filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            local_path TEXT,
            control_acronyms TEXT,
            poam_ids TEXT,
            upload_status TEXT NOT NULL DEFAULT 'pending',
            upload_error TEXT,
            uploaded_at TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (mapping_id) REFERENCES emass_system_mappings(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_mappings_settings ON emass_system_mappings(settings_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_mappings_customer ON emass_system_mappings(heroforge_customer_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_sync_mapping ON emass_sync_history(mapping_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_poam_mapping ON emass_poam_cache(mapping_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_control_mapping ON emass_control_cache(mapping_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_emass_artifacts_mapping ON emass_artifacts(mapping_id)")
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Settings Operations
// ============================================================================

/// Create eMASS settings
pub async fn create_settings(pool: &SqlitePool, settings: &EmassSettings) -> Result<String> {
    let id = if settings.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        settings.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO emass_settings (
            id, name, description, api_url, auth_type, certificate_path,
            certificate_password_encrypted, api_key_encrypted, user_id,
            verify_ssl, timeout_seconds, is_active, last_connected_at,
            connection_status, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
        "#,
    )
    .bind(&id)
    .bind(&settings.name)
    .bind(&settings.description)
    .bind(&settings.api_url)
    .bind(&settings.auth_type)
    .bind(&settings.certificate_path)
    .bind(&settings.certificate_password_encrypted)
    .bind(&settings.api_key_encrypted)
    .bind(&settings.user_id)
    .bind(settings.verify_ssl)
    .bind(settings.timeout_seconds)
    .bind(settings.is_active)
    .bind(&settings.last_connected_at)
    .bind(&settings.connection_status)
    .bind(&settings.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get settings by ID
pub async fn get_settings(pool: &SqlitePool, id: &str) -> Result<Option<EmassSettings>> {
    let settings = sqlx::query_as::<_, EmassSettings>(
        "SELECT * FROM emass_settings WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(settings)
}

/// List all active settings
pub async fn list_settings(pool: &SqlitePool) -> Result<Vec<EmassSettings>> {
    let settings = sqlx::query_as::<_, EmassSettings>(
        "SELECT * FROM emass_settings WHERE is_active = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await?;

    Ok(settings)
}

/// Update settings
pub async fn update_settings(pool: &SqlitePool, settings: &EmassSettings) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE emass_settings
        SET name = ?1, description = ?2, api_url = ?3, auth_type = ?4,
            certificate_path = ?5, certificate_password_encrypted = ?6,
            api_key_encrypted = ?7, user_id = ?8, verify_ssl = ?9,
            timeout_seconds = ?10, is_active = ?11, updated_at = ?12
        WHERE id = ?13
        "#,
    )
    .bind(&settings.name)
    .bind(&settings.description)
    .bind(&settings.api_url)
    .bind(&settings.auth_type)
    .bind(&settings.certificate_path)
    .bind(&settings.certificate_password_encrypted)
    .bind(&settings.api_key_encrypted)
    .bind(&settings.user_id)
    .bind(settings.verify_ssl)
    .bind(settings.timeout_seconds)
    .bind(settings.is_active)
    .bind(&now)
    .bind(&settings.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update connection status
pub async fn update_connection_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let last_connected = if status == "connected" {
        Some(now.clone())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE emass_settings
        SET connection_status = ?1, last_connected_at = COALESCE(?2, last_connected_at), updated_at = ?3
        WHERE id = ?4
        "#,
    )
    .bind(status)
    .bind(&last_connected)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete settings (soft delete)
pub async fn delete_settings(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE emass_settings SET is_active = 0, updated_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// System Mapping Operations
// ============================================================================

/// Create system mapping
pub async fn create_mapping(pool: &SqlitePool, mapping: &EmassSystemMapping) -> Result<String> {
    let id = if mapping.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        mapping.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO emass_system_mappings (
            id, settings_id, emass_system_id, emass_system_name, emass_system_acronym,
            heroforge_customer_id, heroforge_engagement_id, sync_controls, sync_poams,
            sync_artifacts, auto_create_poams, last_sync_at, sync_status, sync_error,
            is_active, created_by, created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        "#,
    )
    .bind(&id)
    .bind(&mapping.settings_id)
    .bind(mapping.emass_system_id)
    .bind(&mapping.emass_system_name)
    .bind(&mapping.emass_system_acronym)
    .bind(&mapping.heroforge_customer_id)
    .bind(&mapping.heroforge_engagement_id)
    .bind(mapping.sync_controls)
    .bind(mapping.sync_poams)
    .bind(mapping.sync_artifacts)
    .bind(mapping.auto_create_poams)
    .bind(&mapping.last_sync_at)
    .bind(&mapping.sync_status)
    .bind(&mapping.sync_error)
    .bind(mapping.is_active)
    .bind(&mapping.created_by)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Get mapping by ID
pub async fn get_mapping(pool: &SqlitePool, id: &str) -> Result<Option<EmassSystemMapping>> {
    let mapping = sqlx::query_as::<_, EmassSystemMapping>(
        "SELECT * FROM emass_system_mappings WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(mapping)
}

/// Get mapping by customer ID
pub async fn get_mapping_by_customer(
    pool: &SqlitePool,
    customer_id: &str,
) -> Result<Option<EmassSystemMapping>> {
    let mapping = sqlx::query_as::<_, EmassSystemMapping>(
        "SELECT * FROM emass_system_mappings WHERE heroforge_customer_id = ?1 AND is_active = 1",
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await?;

    Ok(mapping)
}

/// List mappings for settings
pub async fn list_mappings_for_settings(
    pool: &SqlitePool,
    settings_id: &str,
) -> Result<Vec<EmassSystemMapping>> {
    let mappings = sqlx::query_as::<_, EmassSystemMapping>(
        "SELECT * FROM emass_system_mappings WHERE settings_id = ?1 AND is_active = 1 ORDER BY emass_system_name",
    )
    .bind(settings_id)
    .fetch_all(pool)
    .await?;

    Ok(mappings)
}

/// Update mapping sync status
pub async fn update_mapping_sync_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let last_sync = if status == "success" {
        Some(now.clone())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE emass_system_mappings
        SET sync_status = ?1, sync_error = ?2, last_sync_at = COALESCE(?3, last_sync_at), updated_at = ?4
        WHERE id = ?5
        "#,
    )
    .bind(status)
    .bind(error)
    .bind(&last_sync)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Update mapping configuration
pub async fn update_mapping(pool: &SqlitePool, mapping: &EmassSystemMapping) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE emass_system_mappings
        SET heroforge_customer_id = ?1, heroforge_engagement_id = ?2,
            sync_controls = ?3, sync_poams = ?4, sync_artifacts = ?5,
            auto_create_poams = ?6, is_active = ?7, updated_at = ?8
        WHERE id = ?9
        "#,
    )
    .bind(&mapping.heroforge_customer_id)
    .bind(&mapping.heroforge_engagement_id)
    .bind(mapping.sync_controls)
    .bind(mapping.sync_poams)
    .bind(mapping.sync_artifacts)
    .bind(mapping.auto_create_poams)
    .bind(mapping.is_active)
    .bind(&now)
    .bind(&mapping.id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete mapping (soft delete)
pub async fn delete_mapping(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("UPDATE emass_system_mappings SET is_active = 0, updated_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Sync History Operations
// ============================================================================

/// Create sync history record
pub async fn create_sync_history(pool: &SqlitePool, history: &EmassSyncHistory) -> Result<String> {
    let id = if history.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        history.id.clone()
    };

    sqlx::query(
        r#"
        INSERT INTO emass_sync_history (
            id, mapping_id, sync_type, direction, status, started_at,
            completed_at, controls_synced, poams_created, poams_updated,
            artifacts_uploaded, errors, error_message, sync_details, executed_by
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&history.mapping_id)
    .bind(&history.sync_type)
    .bind(&history.direction)
    .bind(&history.status)
    .bind(&history.started_at)
    .bind(&history.completed_at)
    .bind(history.controls_synced)
    .bind(history.poams_created)
    .bind(history.poams_updated)
    .bind(history.artifacts_uploaded)
    .bind(history.errors)
    .bind(&history.error_message)
    .bind(&history.sync_details)
    .bind(&history.executed_by)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update sync history on completion
pub async fn complete_sync_history(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    controls_synced: i32,
    poams_created: i32,
    poams_updated: i32,
    artifacts_uploaded: i32,
    errors: i32,
    error_message: Option<&str>,
    sync_details: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        UPDATE emass_sync_history
        SET status = ?1, completed_at = ?2, controls_synced = ?3,
            poams_created = ?4, poams_updated = ?5, artifacts_uploaded = ?6,
            errors = ?7, error_message = ?8, sync_details = ?9
        WHERE id = ?10
        "#,
    )
    .bind(status)
    .bind(&now)
    .bind(controls_synced)
    .bind(poams_created)
    .bind(poams_updated)
    .bind(artifacts_uploaded)
    .bind(errors)
    .bind(error_message)
    .bind(sync_details)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get sync history for mapping
pub async fn get_sync_history(
    pool: &SqlitePool,
    mapping_id: &str,
    limit: i32,
) -> Result<Vec<EmassSyncHistory>> {
    let history = sqlx::query_as::<_, EmassSyncHistory>(
        "SELECT * FROM emass_sync_history WHERE mapping_id = ?1 ORDER BY started_at DESC LIMIT ?2",
    )
    .bind(mapping_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(history)
}

// ============================================================================
// POA&M Cache Operations
// ============================================================================

/// Create or update POA&M cache entry
pub async fn upsert_poam_cache(pool: &SqlitePool, poam: &EmassPoamCache) -> Result<String> {
    let id = if poam.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        poam.id.clone()
    };

    // Check if exists
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM emass_poam_cache WHERE mapping_id = ?1 AND emass_poam_id = ?2",
    )
    .bind(&poam.mapping_id)
    .bind(poam.emass_poam_id)
    .fetch_optional(pool)
    .await?;

    if let Some((existing_id,)) = existing {
        // Update
        sqlx::query(
            r#"
            UPDATE emass_poam_cache
            SET control_acronym = ?1, cci = ?2, weakness_description = ?3,
                status = ?4, scheduled_completion_date = ?5, actual_completion_date = ?6,
                milestones = ?7, resources = ?8, heroforge_finding_id = ?9,
                last_emass_update = ?10, last_sync_at = ?11, needs_sync = ?12, local_changes = ?13
            WHERE id = ?14
            "#,
        )
        .bind(&poam.control_acronym)
        .bind(&poam.cci)
        .bind(&poam.weakness_description)
        .bind(&poam.status)
        .bind(&poam.scheduled_completion_date)
        .bind(&poam.actual_completion_date)
        .bind(&poam.milestones)
        .bind(&poam.resources)
        .bind(&poam.heroforge_finding_id)
        .bind(&poam.last_emass_update)
        .bind(&poam.last_sync_at)
        .bind(poam.needs_sync)
        .bind(&poam.local_changes)
        .bind(&existing_id)
        .execute(pool)
        .await?;

        Ok(existing_id)
    } else {
        // Insert
        sqlx::query(
            r#"
            INSERT INTO emass_poam_cache (
                id, mapping_id, emass_poam_id, control_acronym, cci,
                weakness_description, status, scheduled_completion_date,
                actual_completion_date, milestones, resources, heroforge_finding_id,
                last_emass_update, last_sync_at, needs_sync, local_changes
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#,
        )
        .bind(&id)
        .bind(&poam.mapping_id)
        .bind(poam.emass_poam_id)
        .bind(&poam.control_acronym)
        .bind(&poam.cci)
        .bind(&poam.weakness_description)
        .bind(&poam.status)
        .bind(&poam.scheduled_completion_date)
        .bind(&poam.actual_completion_date)
        .bind(&poam.milestones)
        .bind(&poam.resources)
        .bind(&poam.heroforge_finding_id)
        .bind(&poam.last_emass_update)
        .bind(&poam.last_sync_at)
        .bind(poam.needs_sync)
        .bind(&poam.local_changes)
        .execute(pool)
        .await?;

        Ok(id)
    }
}

/// Get POA&Ms for mapping
pub async fn get_poams_for_mapping(
    pool: &SqlitePool,
    mapping_id: &str,
    status: Option<&str>,
) -> Result<Vec<EmassPoamCache>> {
    let mut query = String::from("SELECT * FROM emass_poam_cache WHERE mapping_id = ?1");

    if let Some(s) = status {
        query.push_str(&format!(" AND status = '{}'", s));
    }

    query.push_str(" ORDER BY control_acronym");

    let poams = sqlx::query_as::<_, EmassPoamCache>(&query)
        .bind(mapping_id)
        .fetch_all(pool)
        .await?;

    Ok(poams)
}

/// Get POA&Ms needing sync
pub async fn get_poams_needing_sync(pool: &SqlitePool, mapping_id: &str) -> Result<Vec<EmassPoamCache>> {
    let poams = sqlx::query_as::<_, EmassPoamCache>(
        "SELECT * FROM emass_poam_cache WHERE mapping_id = ?1 AND needs_sync = 1",
    )
    .bind(mapping_id)
    .fetch_all(pool)
    .await?;

    Ok(poams)
}

/// Mark POA&M as synced
pub async fn mark_poam_synced(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE emass_poam_cache SET needs_sync = 0, local_changes = NULL, last_sync_at = ?1 WHERE id = ?2",
    )
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Link POA&M to HeroForge finding
pub async fn link_poam_to_finding(pool: &SqlitePool, poam_id: &str, finding_id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE emass_poam_cache SET heroforge_finding_id = ?1, needs_sync = 1 WHERE id = ?2",
    )
    .bind(finding_id)
    .bind(poam_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Control Cache Operations
// ============================================================================

/// Create or update control cache entry
pub async fn upsert_control_cache(pool: &SqlitePool, control: &EmassControlCache) -> Result<String> {
    let id = if control.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        control.id.clone()
    };

    // Check if exists
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM emass_control_cache WHERE mapping_id = ?1 AND control_acronym = ?2",
    )
    .bind(&control.mapping_id)
    .bind(&control.control_acronym)
    .fetch_optional(pool)
    .await?;

    if let Some((existing_id,)) = existing {
        // Update
        sqlx::query(
            r#"
            UPDATE emass_control_cache
            SET cci = ?1, compliance_status = ?2, implementation_status = ?3,
                responsible_entities = ?4, implementation_narrative = ?5,
                last_emass_update = ?6, last_sync_at = ?7
            WHERE id = ?8
            "#,
        )
        .bind(&control.cci)
        .bind(&control.compliance_status)
        .bind(&control.implementation_status)
        .bind(&control.responsible_entities)
        .bind(&control.implementation_narrative)
        .bind(&control.last_emass_update)
        .bind(&control.last_sync_at)
        .bind(&existing_id)
        .execute(pool)
        .await?;

        Ok(existing_id)
    } else {
        // Insert
        sqlx::query(
            r#"
            INSERT INTO emass_control_cache (
                id, mapping_id, control_acronym, cci, compliance_status,
                implementation_status, responsible_entities, implementation_narrative,
                last_emass_update, last_sync_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(&id)
        .bind(&control.mapping_id)
        .bind(&control.control_acronym)
        .bind(&control.cci)
        .bind(&control.compliance_status)
        .bind(&control.implementation_status)
        .bind(&control.responsible_entities)
        .bind(&control.implementation_narrative)
        .bind(&control.last_emass_update)
        .bind(&control.last_sync_at)
        .execute(pool)
        .await?;

        Ok(id)
    }
}

/// Get controls for mapping
pub async fn get_controls_for_mapping(
    pool: &SqlitePool,
    mapping_id: &str,
) -> Result<Vec<EmassControlCache>> {
    let controls = sqlx::query_as::<_, EmassControlCache>(
        "SELECT * FROM emass_control_cache WHERE mapping_id = ?1 ORDER BY control_acronym",
    )
    .bind(mapping_id)
    .fetch_all(pool)
    .await?;

    Ok(controls)
}

// ============================================================================
// Artifact Operations
// ============================================================================

/// Create artifact record
pub async fn create_artifact(pool: &SqlitePool, artifact: &EmassArtifact) -> Result<String> {
    let id = if artifact.id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        artifact.id.clone()
    };

    let now = Utc::now().to_rfc3339();

    sqlx::query(
        r#"
        INSERT INTO emass_artifacts (
            id, mapping_id, emass_artifact_id, filename, file_type,
            file_size, file_hash, local_path, control_acronyms, poam_ids,
            upload_status, upload_error, uploaded_at, created_by, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
    )
    .bind(&id)
    .bind(&artifact.mapping_id)
    .bind(artifact.emass_artifact_id)
    .bind(&artifact.filename)
    .bind(&artifact.file_type)
    .bind(artifact.file_size)
    .bind(&artifact.file_hash)
    .bind(&artifact.local_path)
    .bind(&artifact.control_acronyms)
    .bind(&artifact.poam_ids)
    .bind(&artifact.upload_status)
    .bind(&artifact.upload_error)
    .bind(&artifact.uploaded_at)
    .bind(&artifact.created_by)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update artifact upload status
pub async fn update_artifact_status(
    pool: &SqlitePool,
    id: &str,
    status: &str,
    emass_artifact_id: Option<i64>,
    error: Option<&str>,
) -> Result<()> {
    let uploaded_at = if status == "uploaded" {
        Some(Utc::now().to_rfc3339())
    } else {
        None
    };

    sqlx::query(
        r#"
        UPDATE emass_artifacts
        SET upload_status = ?1, emass_artifact_id = COALESCE(?2, emass_artifact_id),
            upload_error = ?3, uploaded_at = COALESCE(?4, uploaded_at)
        WHERE id = ?5
        "#,
    )
    .bind(status)
    .bind(emass_artifact_id)
    .bind(error)
    .bind(&uploaded_at)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get artifacts for mapping
pub async fn get_artifacts_for_mapping(
    pool: &SqlitePool,
    mapping_id: &str,
    status: Option<&str>,
) -> Result<Vec<EmassArtifact>> {
    let mut query = String::from("SELECT * FROM emass_artifacts WHERE mapping_id = ?1");

    if let Some(s) = status {
        query.push_str(&format!(" AND upload_status = '{}'", s));
    }

    query.push_str(" ORDER BY created_at DESC");

    let artifacts = sqlx::query_as::<_, EmassArtifact>(&query)
        .bind(mapping_id)
        .fetch_all(pool)
        .await?;

    Ok(artifacts)
}

/// Get pending artifacts for upload
pub async fn get_pending_artifacts(pool: &SqlitePool, mapping_id: &str) -> Result<Vec<EmassArtifact>> {
    let artifacts = sqlx::query_as::<_, EmassArtifact>(
        "SELECT * FROM emass_artifacts WHERE mapping_id = ?1 AND upload_status = 'pending' ORDER BY created_at",
    )
    .bind(mapping_id)
    .fetch_all(pool)
    .await?;

    Ok(artifacts)
}
