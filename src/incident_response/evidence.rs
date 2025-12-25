//! Evidence Collection Module
//!
//! Provides evidence management for incident response:
//! - Evidence types: file, memory dump, screenshot, log extract, network capture
//! - Chain of custody tracking (who collected, when, hash verification)
//! - Evidence storage with integrity hashes (SHA-256)
//! - Evidence notes and tags

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

/// Create a new evidence record
pub async fn create_evidence(
    pool: &SqlitePool,
    incident_id: &str,
    collected_by: &str,
    request: CreateEvidenceRequest,
) -> Result<Evidence> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Validate evidence type
    let _: EvidenceType = request.evidence_type.parse()?;

    let evidence = sqlx::query_as::<_, Evidence>(
        r#"
        INSERT INTO incident_evidence
        (id, incident_id, evidence_type, filename, file_hash, file_size, storage_path,
         collected_by, collected_at, notes, tags)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(incident_id)
    .bind(&request.evidence_type)
    .bind(&request.filename)
    .bind(&request.file_hash)
    .bind(request.file_size)
    .bind(&request.storage_path)
    .bind(collected_by)
    .bind(now)
    .bind(&request.notes)
    .bind(&request.tags)
    .fetch_one(pool)
    .await?;

    // Create initial chain of custody entry
    add_custody_entry(
        pool,
        &id,
        collected_by,
        "collected",
        Some("Initial evidence collection"),
    )
    .await?;

    Ok(evidence)
}

/// Get a single evidence record by ID
pub async fn get_evidence(pool: &SqlitePool, evidence_id: &str) -> Result<Evidence> {
    let evidence = sqlx::query_as::<_, Evidence>(
        "SELECT * FROM incident_evidence WHERE id = ?1"
    )
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;

    Ok(evidence)
}

/// Get evidence with collector info and custody count
pub async fn get_evidence_with_details(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<EvidenceWithDetails> {
    let evidence = get_evidence(pool, evidence_id).await?;

    let collector_name: Option<String> = sqlx::query_scalar(
        "SELECT username FROM users WHERE id = ?1"
    )
    .bind(&evidence.collected_by)
    .fetch_optional(pool)
    .await?;

    let custody_entries: i32 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence_chain_of_custody WHERE evidence_id = ?1"
    )
    .bind(evidence_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(EvidenceWithDetails {
        evidence,
        collector_name,
        custody_entries,
    })
}

/// Get all evidence for an incident
pub async fn get_incident_evidence(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<Evidence>> {
    let evidence = sqlx::query_as::<_, Evidence>(
        "SELECT * FROM incident_evidence WHERE incident_id = ?1 ORDER BY collected_at DESC"
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    Ok(evidence)
}

/// Get all evidence for an incident with details
pub async fn get_incident_evidence_with_details(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<Vec<EvidenceWithDetails>> {
    let evidence_list = get_incident_evidence(pool, incident_id).await?;

    let mut results = Vec::with_capacity(evidence_list.len());
    for evidence in evidence_list {
        let collector_name: Option<String> = sqlx::query_scalar(
            "SELECT username FROM users WHERE id = ?1"
        )
        .bind(&evidence.collected_by)
        .fetch_optional(pool)
        .await?;

        let custody_entries: i32 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM evidence_chain_of_custody WHERE evidence_id = ?1"
        )
        .bind(&evidence.id)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        results.push(EvidenceWithDetails {
            evidence,
            collector_name,
            custody_entries,
        });
    }

    Ok(results)
}

/// Get evidence filtered by type
pub async fn get_evidence_by_type(
    pool: &SqlitePool,
    incident_id: &str,
    evidence_type: &str,
) -> Result<Vec<Evidence>> {
    let evidence = sqlx::query_as::<_, Evidence>(
        "SELECT * FROM incident_evidence WHERE incident_id = ?1 AND evidence_type = ?2 ORDER BY collected_at DESC"
    )
    .bind(incident_id)
    .bind(evidence_type)
    .fetch_all(pool)
    .await?;

    Ok(evidence)
}

/// Update evidence notes and tags
pub async fn update_evidence(
    pool: &SqlitePool,
    evidence_id: &str,
    notes: Option<&str>,
    tags: Option<&str>,
) -> Result<Evidence> {
    let existing = get_evidence(pool, evidence_id).await?;

    let new_notes = notes.map(|s| s.to_string()).or(existing.notes);
    let new_tags = tags.map(|s| s.to_string()).or(existing.tags);

    let evidence = sqlx::query_as::<_, Evidence>(
        r#"
        UPDATE incident_evidence
        SET notes = ?1, tags = ?2
        WHERE id = ?3
        RETURNING *
        "#,
    )
    .bind(&new_notes)
    .bind(&new_tags)
    .bind(evidence_id)
    .fetch_one(pool)
    .await?;

    Ok(evidence)
}

/// Delete an evidence record (should be used carefully - may violate chain of custody)
pub async fn delete_evidence(pool: &SqlitePool, evidence_id: &str) -> Result<()> {
    // First delete custody chain
    sqlx::query("DELETE FROM evidence_chain_of_custody WHERE evidence_id = ?1")
        .bind(evidence_id)
        .execute(pool)
        .await?;

    // Then delete evidence
    sqlx::query("DELETE FROM incident_evidence WHERE id = ?1")
        .bind(evidence_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Verify evidence integrity by checking hash
pub fn verify_evidence_hash(expected_hash: &str, actual_hash: &str) -> bool {
    expected_hash.to_lowercase() == actual_hash.to_lowercase()
}

// ============================================================================
// Chain of Custody Functions
// ============================================================================

/// Add a chain of custody entry
pub async fn add_custody_entry(
    pool: &SqlitePool,
    evidence_id: &str,
    actor_id: &str,
    action: &str,
    notes: Option<&str>,
) -> Result<ChainOfCustody> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let entry = sqlx::query_as::<_, ChainOfCustody>(
        r#"
        INSERT INTO evidence_chain_of_custody
        (id, evidence_id, action, actor_id, timestamp, notes)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(evidence_id)
    .bind(action)
    .bind(actor_id)
    .bind(now)
    .bind(notes)
    .fetch_one(pool)
    .await?;

    Ok(entry)
}

/// Get chain of custody for an evidence item
pub async fn get_custody_chain(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<ChainOfCustody>> {
    let entries = sqlx::query_as::<_, ChainOfCustody>(
        "SELECT * FROM evidence_chain_of_custody WHERE evidence_id = ?1 ORDER BY timestamp ASC"
    )
    .bind(evidence_id)
    .fetch_all(pool)
    .await?;

    Ok(entries)
}

/// Get chain of custody with actor information
pub async fn get_custody_chain_with_actors(
    pool: &SqlitePool,
    evidence_id: &str,
) -> Result<Vec<ChainOfCustodyWithActor>> {
    let entries = get_custody_chain(pool, evidence_id).await?;

    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let actor_name: Option<String> = sqlx::query_scalar(
            "SELECT username FROM users WHERE id = ?1"
        )
        .bind(&entry.actor_id)
        .fetch_optional(pool)
        .await?;

        results.push(ChainOfCustodyWithActor {
            entry,
            actor_name,
        });
    }

    Ok(results)
}

/// Predefined custody actions
pub mod custody_actions {
    /// Evidence was initially collected
    pub const COLLECTED: &str = "collected";
    /// Evidence was transferred to another person
    pub const TRANSFERRED: &str = "transferred";
    /// Evidence was analyzed
    pub const ANALYZED: &str = "analyzed";
    /// Evidence was stored in secure location
    pub const STORED: &str = "stored";
    /// Evidence was accessed for review
    pub const ACCESSED: &str = "accessed";
    /// Evidence was copied/duplicated
    pub const COPIED: &str = "copied";
    /// Evidence was verified (hash check)
    pub const VERIFIED: &str = "verified";
    /// Evidence was exported
    pub const EXPORTED: &str = "exported";
}

/// Generate evidence summary for an incident
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvidenceSummary {
    pub incident_id: String,
    pub total_evidence: usize,
    pub total_size_bytes: i64,
    pub by_type: Vec<(String, usize)>,
    pub collectors: Vec<String>,
    pub date_range: Option<(String, String)>,
}

pub async fn get_evidence_summary(
    pool: &SqlitePool,
    incident_id: &str,
) -> Result<EvidenceSummary> {
    let evidence_list = get_incident_evidence(pool, incident_id).await?;

    let total_evidence = evidence_list.len();
    let total_size_bytes: i64 = evidence_list.iter().map(|e| e.file_size).sum();

    // Count by type
    let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for evidence in &evidence_list {
        *type_counts.entry(evidence.evidence_type.clone()).or_insert(0) += 1;
    }
    let mut by_type: Vec<(String, usize)> = type_counts.into_iter().collect();
    by_type.sort_by(|a, b| b.1.cmp(&a.1));

    // Get unique collectors
    let mut collectors: Vec<String> = evidence_list
        .iter()
        .map(|e| e.collected_by.clone())
        .collect();
    collectors.sort();
    collectors.dedup();

    // Date range
    let date_range = if !evidence_list.is_empty() {
        let min_date = evidence_list
            .iter()
            .min_by_key(|e| e.collected_at)
            .map(|e| e.collected_at.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        let max_date = evidence_list
            .iter()
            .max_by_key(|e| e.collected_at)
            .map(|e| e.collected_at.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        min_date.zip(max_date)
    } else {
        None
    };

    Ok(EvidenceSummary {
        incident_id: incident_id.to_string(),
        total_evidence,
        total_size_bytes,
        by_type,
        collectors,
        date_range,
    })
}

/// Format file size for display
pub fn format_file_size(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}
