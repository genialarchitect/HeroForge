//! Database operations for Threat Hunting module
//!
//! This module handles storage and retrieval of:
//! - IOCs (Indicators of Compromise)
//! - IOC matches
//! - MITRE ATT&CK technique mappings
//! - Detection mappings
//! - Hunting playbooks
//! - Hunting sessions
//! - Retrospective searches

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::debug;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::threat_hunting::{
    ioc::{Ioc, IocType, IocSource, IocStatus, IocSeverity, IocMatch, IocFilter, CreateIocRequest, UpdateIocRequest},
    mitre::{DetectionMapping, CoverageLevel, CreateDetectionMappingRequest},
    playbooks::{HuntingPlaybook, HuntingSession, SessionStatus, PlaybookCategory, DifficultyLevel, StepProgress, HuntingFinding, SessionNote, CreatePlaybookRequest, StartSessionRequest, AddFindingRequest},
    retrospective::{RetrospectiveSearch, SearchStatus, SearchResult, SearchSourceType, InlineIoc, MatchContext, CreateSearchRequest},
};

/// Initialize threat hunting database tables
pub async fn create_threat_hunting_tables(pool: &SqlitePool) -> Result<()> {
    // IOCs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS iocs (
            id TEXT PRIMARY KEY,
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            severity TEXT NOT NULL DEFAULT 'medium',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            tags TEXT,
            user_id TEXT NOT NULL,
            metadata TEXT,
            threat_actor TEXT,
            mitre_techniques TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(ioc_type, value)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // IOC matches table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ioc_matches (
            id TEXT PRIMARY KEY,
            ioc_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            matched_at TEXT NOT NULL,
            context TEXT,
            FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // MITRE techniques table (cached/supplementary data)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            id TEXT PRIMARY KEY,
            technique_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            description TEXT,
            detection TEXT,
            platforms TEXT,
            data_sources TEXT,
            mitigations TEXT,
            url TEXT,
            modified TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Detection to MITRE mapping table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS detection_mitre_mapping (
            id TEXT PRIMARY KEY,
            detection_name TEXT NOT NULL,
            detection_query TEXT,
            technique_ids TEXT NOT NULL,
            data_sources TEXT,
            detection_type TEXT NOT NULL DEFAULT 'signature',
            coverage_level TEXT NOT NULL DEFAULT 'low',
            notes TEXT,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Hunting playbooks table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hunting_playbooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            difficulty TEXT NOT NULL DEFAULT 'intermediate',
            estimated_duration TEXT,
            steps_json TEXT NOT NULL,
            tags TEXT,
            mitre_tactics TEXT,
            mitre_techniques TEXT,
            is_builtin INTEGER NOT NULL DEFAULT 0,
            user_id TEXT,
            version TEXT NOT NULL DEFAULT '1.0',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Hunting sessions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS hunting_sessions (
            id TEXT PRIMARY KEY,
            playbook_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            current_step INTEGER NOT NULL DEFAULT 1,
            step_progress_json TEXT NOT NULL DEFAULT '[]',
            findings_json TEXT NOT NULL DEFAULT '[]',
            notes_json TEXT NOT NULL DEFAULT '[]',
            time_spent_minutes INTEGER NOT NULL DEFAULT 0,
            scope TEXT,
            hypothesis TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            user_id TEXT NOT NULL,
            FOREIGN KEY (playbook_id) REFERENCES hunting_playbooks(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Retrospective searches table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS retrospective_searches (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            query TEXT,
            ioc_ids_json TEXT,
            ioc_values_json TEXT,
            time_start TEXT NOT NULL,
            time_end TEXT NOT NULL,
            sources_json TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            results_count INTEGER NOT NULL DEFAULT 0,
            progress INTEGER NOT NULL DEFAULT 0,
            error_message TEXT,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Retrospective search results table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS retrospective_search_results (
            id TEXT PRIMARY KEY,
            search_id TEXT NOT NULL,
            matched_ioc TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            source_type TEXT NOT NULL,
            source_id TEXT NOT NULL,
            match_timestamp TEXT NOT NULL,
            context_json TEXT,
            severity TEXT NOT NULL DEFAULT 'medium',
            metadata TEXT,
            FOREIGN KEY (search_id) REFERENCES retrospective_searches(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_iocs_user ON iocs(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ioc_matches_ioc_id ON ioc_matches(ioc_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_ioc_matches_source ON ioc_matches(source_type, source_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunting_sessions_user ON hunting_sessions(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunting_sessions_playbook ON hunting_sessions(playbook_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_retrospective_searches_user ON retrospective_searches(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_search_results_search ON retrospective_search_results(search_id)")
        .execute(pool)
        .await?;

    // Hunt hypotheses table (Phase 4 Sprint 1)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hunt_hypotheses (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            query TEXT NOT NULL,
            expected_outcome TEXT,
            status TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Hunt campaigns table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hunt_campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            start_date TEXT,
            end_date TEXT,
            status TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Hunt executions table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hunt_executions (
            id TEXT PRIMARY KEY,
            hypothesis_id TEXT,
            campaign_id TEXT,
            executed_at TEXT NOT NULL,
            results TEXT NOT NULL,
            findings_count INTEGER NOT NULL DEFAULT 0,
            false_positives INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            FOREIGN KEY(hypothesis_id) REFERENCES hunt_hypotheses(id) ON DELETE CASCADE,
            FOREIGN KEY(campaign_id) REFERENCES hunt_campaigns(id) ON DELETE CASCADE
        )"
    )
    .execute(pool)
    .await?;

    // Hunt queries table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hunt_queries (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            query_dsl TEXT NOT NULL,
            category TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            last_used TEXT
        )"
    )
    .execute(pool)
    .await?;

    // Hunt notebooks table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hunt_notebooks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            shared_with TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"
    )
    .execute(pool)
    .await?;

    // Create indexes for hunt tables
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_hypotheses_status ON hunt_hypotheses(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_hypotheses_created_by ON hunt_hypotheses(created_by)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_executions_hypothesis_id ON hunt_executions(hypothesis_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_executions_campaign_id ON hunt_executions(campaign_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_executions_executed_at ON hunt_executions(executed_at)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_campaigns_status ON hunt_campaigns(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_queries_category ON hunt_queries(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_hunt_notebooks_created_by ON hunt_notebooks(created_by)")
        .execute(pool)
        .await?;

    debug!("Threat hunting tables created successfully");
    Ok(())
}

// ============================================================================
// IOC Operations
// ============================================================================

/// Create a new IOC
pub async fn create_ioc(pool: &SqlitePool, user_id: &str, request: &CreateIocRequest) -> Result<Ioc> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    let mitre_json = request.mitre_techniques.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_default())
        .unwrap_or_else(|| "[]".to_string());

    let metadata_json = request.metadata.as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_default());

    let source = request.source.unwrap_or(IocSource::Manual);
    let severity = request.severity.unwrap_or(IocSeverity::Medium);

    sqlx::query(
        r#"
        INSERT INTO iocs (id, ioc_type, value, description, source, status, severity,
                         first_seen, last_seen, tags, user_id, metadata, threat_actor,
                         mitre_techniques, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(request.ioc_type.to_string())
    .bind(&request.value)
    .bind(&request.description)
    .bind(source.to_string())
    .bind(IocStatus::Active.to_string())
    .bind(severity.to_string())
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(&tags_json)
    .bind(user_id)
    .bind(&metadata_json)
    .bind(&request.threat_actor)
    .bind(&mitre_json)
    .bind(request.expires_at.map(|d| d.to_rfc3339()))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(Ioc {
        id,
        ioc_type: request.ioc_type,
        value: request.value.clone(),
        description: request.description.clone(),
        source,
        status: IocStatus::Active,
        severity,
        first_seen: now,
        last_seen: now,
        tags: request.tags.clone().unwrap_or_default(),
        user_id: user_id.to_string(),
        metadata: request.metadata.clone(),
        threat_actor: request.threat_actor.clone(),
        mitre_techniques: request.mitre_techniques.clone().unwrap_or_default(),
        expires_at: request.expires_at,
        created_at: now,
        updated_at: now,
    })
}

/// Get an IOC by ID
pub async fn get_ioc_by_id(pool: &SqlitePool, id: &str) -> Result<Option<Ioc>> {
    let row = sqlx::query_as::<_, IocRow>(
        "SELECT * FROM iocs WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_ioc()))
}

/// Get IOCs by filter
pub async fn get_iocs(pool: &SqlitePool, user_id: &str, filter: &IocFilter) -> Result<Vec<Ioc>> {
    let mut query = "SELECT * FROM iocs WHERE user_id = ?".to_string();
    let mut bindings: Vec<String> = vec![user_id.to_string()];

    if let Some(ioc_type) = &filter.ioc_type {
        query.push_str(" AND ioc_type = ?");
        bindings.push(ioc_type.to_string());
    }

    if let Some(status) = &filter.status {
        query.push_str(" AND status = ?");
        bindings.push(status.to_string());
    }

    if let Some(severity) = &filter.severity {
        query.push_str(" AND severity = ?");
        bindings.push(severity.to_string());
    }

    if let Some(source) = &filter.source {
        query.push_str(" AND source = ?");
        bindings.push(source.to_string());
    }

    if let Some(tag) = &filter.tag {
        query.push_str(" AND tags LIKE ?");
        bindings.push(format!("%{}%", tag));
    }

    if let Some(threat_actor) = &filter.threat_actor {
        query.push_str(" AND threat_actor LIKE ?");
        bindings.push(format!("%{}%", threat_actor));
    }

    if let Some(mitre) = &filter.mitre_technique {
        query.push_str(" AND mitre_techniques LIKE ?");
        bindings.push(format!("%{}%", mitre));
    }

    if let Some(search) = &filter.search {
        query.push_str(" AND (value LIKE ? OR description LIKE ?)");
        bindings.push(format!("%{}%", search));
        bindings.push(format!("%{}%", search));
    }

    query.push_str(" ORDER BY created_at DESC");

    if let Some(limit) = filter.limit {
        query.push_str(&format!(" LIMIT {}", limit));
    }

    if let Some(offset) = filter.offset {
        query.push_str(&format!(" OFFSET {}", offset));
    }

    // Build dynamic query
    let mut query_builder = sqlx::query_as::<_, IocRow>(&query);
    for binding in bindings {
        query_builder = query_builder.bind(binding);
    }

    let rows = query_builder.fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.into_ioc()).collect())
}

/// Update an IOC
pub async fn update_ioc(pool: &SqlitePool, id: &str, request: &UpdateIocRequest) -> Result<bool> {
    let now = Utc::now();

    let mut updates = Vec::new();
    let mut bindings: Vec<String> = Vec::new();

    if let Some(desc) = &request.description {
        updates.push("description = ?");
        bindings.push(desc.clone());
    }

    if let Some(status) = &request.status {
        updates.push("status = ?");
        bindings.push(status.to_string());
    }

    if let Some(severity) = &request.severity {
        updates.push("severity = ?");
        bindings.push(severity.to_string());
    }

    if let Some(tags) = &request.tags {
        updates.push("tags = ?");
        bindings.push(serde_json::to_string(tags)?);
    }

    if let Some(actor) = &request.threat_actor {
        updates.push("threat_actor = ?");
        bindings.push(actor.clone());
    }

    if let Some(mitre) = &request.mitre_techniques {
        updates.push("mitre_techniques = ?");
        bindings.push(serde_json::to_string(mitre)?);
    }

    if request.expires_at.is_some() {
        updates.push("expires_at = ?");
        bindings.push(request.expires_at.map(|d| d.to_rfc3339()).unwrap_or_default());
    }

    if let Some(metadata) = &request.metadata {
        updates.push("metadata = ?");
        bindings.push(serde_json::to_string(metadata)?);
    }

    if updates.is_empty() {
        return Ok(false);
    }

    updates.push("updated_at = ?");
    bindings.push(now.to_rfc3339());

    bindings.push(id.to_string());

    let query = format!(
        "UPDATE iocs SET {} WHERE id = ?",
        updates.join(", ")
    );

    let mut query_builder = sqlx::query(&query);
    for binding in bindings {
        query_builder = query_builder.bind(binding);
    }

    let result = query_builder.execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// Delete an IOC
pub async fn delete_ioc(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM iocs WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Update IOC last_seen timestamp
pub async fn update_ioc_last_seen(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE iocs SET last_seen = ?, updated_at = ? WHERE id = ?")
        .bind(now.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Record an IOC match
pub async fn create_ioc_match(
    pool: &SqlitePool,
    ioc_id: &str,
    source_type: &str,
    source_id: &str,
    context: Option<serde_json::Value>,
) -> Result<IocMatch> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let context_json = context.as_ref().map(|c| serde_json::to_string(c).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO ioc_matches (id, ioc_id, source_type, source_id, matched_at, context)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(ioc_id)
    .bind(source_type)
    .bind(source_id)
    .bind(now.to_rfc3339())
    .bind(&context_json)
    .execute(pool)
    .await?;

    // Update IOC last_seen
    update_ioc_last_seen(pool, ioc_id).await?;

    Ok(IocMatch {
        id,
        ioc_id: ioc_id.to_string(),
        source_type: source_type.to_string(),
        source_id: source_id.to_string(),
        matched_at: now,
        context,
        ioc: None,
    })
}

/// Get matches for an IOC
pub async fn get_ioc_matches(pool: &SqlitePool, ioc_id: &str, limit: i32) -> Result<Vec<IocMatch>> {
    let rows = sqlx::query_as::<_, IocMatchRow>(
        "SELECT * FROM ioc_matches WHERE ioc_id = ? ORDER BY matched_at DESC LIMIT ?"
    )
    .bind(ioc_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_match()).collect())
}

/// Bulk import IOCs
pub async fn bulk_import_iocs(pool: &SqlitePool, user_id: &str, iocs: &[CreateIocRequest]) -> Result<(usize, usize, Vec<String>)> {
    let mut imported = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    for ioc in iocs {
        match create_ioc(pool, user_id, ioc).await {
            Ok(_) => imported += 1,
            Err(e) => {
                if e.to_string().contains("UNIQUE constraint failed") {
                    skipped += 1;
                } else {
                    errors.push(format!("{}: {}", ioc.value, e));
                }
            }
        }
    }

    Ok((imported, skipped, errors))
}

// ============================================================================
// Detection Mapping Operations
// ============================================================================

/// Create a detection mapping
pub async fn create_detection_mapping(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateDetectionMappingRequest,
) -> Result<DetectionMapping> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let techniques_json = serde_json::to_string(&request.technique_ids)?;
    let data_sources_json = request.data_sources.as_ref()
        .map(|d| serde_json::to_string(d).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    let detection_type = request.detection_type.clone().unwrap_or_else(|| "signature".to_string());
    let coverage_level = request.coverage_level.unwrap_or(CoverageLevel::Low);

    sqlx::query(
        r#"
        INSERT INTO detection_mitre_mapping (id, detection_name, detection_query, technique_ids,
                                            data_sources, detection_type, coverage_level, notes,
                                            user_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.detection_name)
    .bind(&request.detection_query)
    .bind(&techniques_json)
    .bind(&data_sources_json)
    .bind(&detection_type)
    .bind(coverage_level.to_string())
    .bind(&request.notes)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(DetectionMapping {
        id,
        detection_name: request.detection_name.clone(),
        detection_query: request.detection_query.clone(),
        technique_ids: request.technique_ids.clone(),
        data_sources: request.data_sources.clone().unwrap_or_default(),
        detection_type,
        coverage_level,
        notes: request.notes.clone(),
        user_id: user_id.to_string(),
        created_at: now,
    })
}

/// Get all detection mappings for a user
pub async fn get_detection_mappings(pool: &SqlitePool, user_id: &str) -> Result<Vec<DetectionMapping>> {
    let rows = sqlx::query_as::<_, DetectionMappingRow>(
        "SELECT * FROM detection_mitre_mapping WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_mapping()).collect())
}

/// Get detection mappings for specific techniques
pub async fn get_mappings_for_techniques(pool: &SqlitePool, technique_ids: &[String]) -> Result<Vec<DetectionMapping>> {
    let mut mappings = Vec::new();

    let rows = sqlx::query_as::<_, DetectionMappingRow>(
        "SELECT * FROM detection_mitre_mapping"
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let mapping = row.into_mapping();
        if mapping.technique_ids.iter().any(|t| technique_ids.contains(t)) {
            mappings.push(mapping);
        }
    }

    Ok(mappings)
}

/// Delete a detection mapping
pub async fn delete_detection_mapping(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM detection_mitre_mapping WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

// ============================================================================
// Playbook Operations
// ============================================================================

/// Create a hunting playbook
pub async fn create_playbook(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreatePlaybookRequest,
) -> Result<HuntingPlaybook> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    // Convert step requests to full steps with numbering
    let steps: Vec<crate::threat_hunting::playbooks::PlaybookStep> = request.steps.iter().enumerate().map(|(i, s)| {
        crate::threat_hunting::playbooks::PlaybookStep {
            step_number: (i + 1) as u32,
            title: s.title.clone(),
            description: s.description.clone(),
            objective: s.objective.clone(),
            expected_duration: s.expected_duration.clone(),
            queries: s.queries.clone().unwrap_or_default(),
            evidence_checkpoints: s.evidence_checkpoints.clone().unwrap_or_default(),
            indicators_to_find: s.indicators_to_find.clone().unwrap_or_default(),
            decision_points: s.decision_points.clone().unwrap_or_default(),
            mitre_techniques: s.mitre_techniques.clone().unwrap_or_default(),
            prerequisites: s.prerequisites.clone().unwrap_or_default(),
            notes: s.notes.clone(),
        }
    }).collect();

    let steps_json = serde_json::to_string(&steps)?;
    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    let mitre_tactics: Vec<crate::threat_hunting::mitre::MitreTactic> = request.mitre_tactics.as_ref()
        .map(|t| t.iter().filter_map(|s| crate::threat_hunting::mitre::MitreTactic::from_str(s)).collect())
        .unwrap_or_default();
    let tactics_json = serde_json::to_string(&mitre_tactics)?;
    let techniques_json = request.mitre_techniques.as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    let difficulty = request.difficulty.unwrap_or(DifficultyLevel::Intermediate);
    let estimated_duration = request.estimated_duration.clone().unwrap_or_else(|| "2-4 hours".to_string());

    sqlx::query(
        r#"
        INSERT INTO hunting_playbooks (id, name, description, category, difficulty, estimated_duration,
                                       steps_json, tags, mitre_tactics, mitre_techniques, is_builtin,
                                       user_id, version, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, '1.0', ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.category.to_string())
    .bind(difficulty.to_string())
    .bind(&estimated_duration)
    .bind(&steps_json)
    .bind(&tags_json)
    .bind(&tactics_json)
    .bind(&techniques_json)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(HuntingPlaybook {
        id,
        name: request.name.clone(),
        description: request.description.clone(),
        category: request.category,
        difficulty,
        estimated_duration,
        steps,
        tags: request.tags.clone().unwrap_or_default(),
        mitre_tactics,
        mitre_techniques: request.mitre_techniques.clone().unwrap_or_default(),
        is_builtin: false,
        user_id: Some(user_id.to_string()),
        created_at: now,
        updated_at: now,
        version: "1.0".to_string(),
    })
}

/// Get playbook by ID
pub async fn get_playbook_by_id(pool: &SqlitePool, id: &str) -> Result<Option<HuntingPlaybook>> {
    let row = sqlx::query_as::<_, PlaybookRow>(
        "SELECT * FROM hunting_playbooks WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_playbook()))
}

/// Get all playbooks (user's + built-in)
pub async fn get_playbooks(pool: &SqlitePool, user_id: &str) -> Result<Vec<HuntingPlaybook>> {
    let rows = sqlx::query_as::<_, PlaybookRow>(
        "SELECT * FROM hunting_playbooks WHERE user_id = ? OR is_builtin = 1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_playbook()).collect())
}

/// Get playbooks by category
pub async fn get_playbooks_by_category(pool: &SqlitePool, category: PlaybookCategory) -> Result<Vec<HuntingPlaybook>> {
    let rows = sqlx::query_as::<_, PlaybookRow>(
        "SELECT * FROM hunting_playbooks WHERE category = ? ORDER BY created_at DESC"
    )
    .bind(category.to_string())
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_playbook()).collect())
}

/// Delete a playbook
pub async fn delete_playbook(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM hunting_playbooks WHERE id = ? AND is_builtin = 0")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Seed built-in playbooks
pub async fn seed_builtin_playbooks(pool: &SqlitePool) -> Result<()> {
    use log::info;

    let playbooks = crate::threat_hunting::playbooks::BuiltinPlaybooks::get_all();
    info!("Seeding {} built-in threat hunting playbooks", playbooks.len());

    let mut inserted = 0;
    for playbook in &playbooks {
        // Check if already exists
        let exists = sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM hunting_playbooks WHERE id = ?"
        )
        .bind(&playbook.id)
        .fetch_one(pool)
        .await?;

        if exists > 0 {
            continue;
        }

        let steps_json = serde_json::to_string(&playbook.steps)?;
        let tags_json = serde_json::to_string(&playbook.tags)?;
        let tactics_json = serde_json::to_string(&playbook.mitre_tactics)?;
        let techniques_json = serde_json::to_string(&playbook.mitre_techniques)?;

        sqlx::query(
            r#"
            INSERT INTO hunting_playbooks (id, name, description, category, difficulty, estimated_duration,
                                           steps_json, tags, mitre_tactics, mitre_techniques, is_builtin,
                                           user_id, version, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?, ?, ?)
            "#,
        )
        .bind(&playbook.id)
        .bind(&playbook.name)
        .bind(&playbook.description)
        .bind(playbook.category.to_string())
        .bind(playbook.difficulty.to_string())
        .bind(&playbook.estimated_duration)
        .bind(&steps_json)
        .bind(&tags_json)
        .bind(&tactics_json)
        .bind(&techniques_json)
        .bind(&playbook.version)
        .bind(playbook.created_at.to_rfc3339())
        .bind(playbook.updated_at.to_rfc3339())
        .execute(pool)
        .await?;

        inserted += 1;
    }

    if inserted > 0 {
        info!("Seeded {} new threat hunting playbooks", inserted);
    }
    Ok(())
}

// ============================================================================
// Hunting Session Operations
// ============================================================================

/// Start a hunting session
pub async fn start_hunting_session(
    pool: &SqlitePool,
    user_id: &str,
    request: &StartSessionRequest,
) -> Result<HuntingSession> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO hunting_sessions (id, playbook_id, status, current_step, step_progress_json,
                                      findings_json, notes_json, time_spent_minutes, scope,
                                      hypothesis, started_at, user_id)
        VALUES (?, ?, 'active', 1, '[]', '[]', '[]', 0, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.playbook_id)
    .bind(&request.scope)
    .bind(&request.hypothesis)
    .bind(now.to_rfc3339())
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(HuntingSession {
        id,
        playbook_id: request.playbook_id.clone(),
        status: SessionStatus::Active,
        current_step: 1,
        step_progress: Vec::new(),
        findings: Vec::new(),
        notes: Vec::new(),
        time_spent_minutes: 0,
        started_at: now,
        completed_at: None,
        user_id: user_id.to_string(),
        scope: request.scope.clone(),
        hypothesis: request.hypothesis.clone(),
    })
}

/// Get session by ID
pub async fn get_session_by_id(pool: &SqlitePool, id: &str) -> Result<Option<HuntingSession>> {
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT * FROM hunting_sessions WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_session()))
}

/// Get user's sessions
pub async fn get_user_sessions(pool: &SqlitePool, user_id: &str) -> Result<Vec<HuntingSession>> {
    let rows = sqlx::query_as::<_, SessionRow>(
        "SELECT * FROM hunting_sessions WHERE user_id = ? ORDER BY started_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_session()).collect())
}

/// Update session status
pub async fn update_session_status(pool: &SqlitePool, id: &str, status: SessionStatus) -> Result<bool> {
    let now = Utc::now();
    let completed_at = if status == SessionStatus::Completed {
        Some(now.to_rfc3339())
    } else {
        None
    };

    let result = sqlx::query(
        "UPDATE hunting_sessions SET status = ?, completed_at = ? WHERE id = ?"
    )
    .bind(status.to_string())
    .bind(completed_at)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Update session progress
pub async fn update_session_progress(
    pool: &SqlitePool,
    id: &str,
    current_step: u32,
    step_progress: &[StepProgress],
    time_spent: u32,
) -> Result<bool> {
    let progress_json = serde_json::to_string(step_progress)?;

    let result = sqlx::query(
        "UPDATE hunting_sessions SET current_step = ?, step_progress_json = ?, time_spent_minutes = ? WHERE id = ?"
    )
    .bind(current_step as i32)
    .bind(&progress_json)
    .bind(time_spent as i32)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Add finding to session
pub async fn add_session_finding(
    pool: &SqlitePool,
    session_id: &str,
    request: &AddFindingRequest,
) -> Result<HuntingFinding> {
    let finding_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let finding = HuntingFinding {
        id: finding_id.clone(),
        title: request.title.clone(),
        description: request.description.clone(),
        severity: request.severity.clone(),
        found_at_step: request.step_number,
        related_iocs: request.related_iocs.clone().unwrap_or_default(),
        mitre_techniques: request.mitre_techniques.clone().unwrap_or_default(),
        evidence: request.evidence.clone().unwrap_or_default(),
        recommendations: request.recommendations.clone().unwrap_or_default(),
        created_at: now,
    };

    // Get current findings and append
    let current = sqlx::query_scalar::<_, String>(
        "SELECT findings_json FROM hunting_sessions WHERE id = ?"
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    let mut findings: Vec<HuntingFinding> = serde_json::from_str(&current).unwrap_or_default();
    findings.push(finding.clone());

    let findings_json = serde_json::to_string(&findings)?;

    sqlx::query("UPDATE hunting_sessions SET findings_json = ? WHERE id = ?")
        .bind(&findings_json)
        .bind(session_id)
        .execute(pool)
        .await?;

    Ok(finding)
}

/// Add note to session
pub async fn add_session_note(
    pool: &SqlitePool,
    session_id: &str,
    step_number: Option<u32>,
    content: &str,
) -> Result<SessionNote> {
    let note_id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let note = SessionNote {
        id: note_id.clone(),
        step_number,
        content: content.to_string(),
        created_at: now,
    };

    // Get current notes and append
    let current = sqlx::query_scalar::<_, String>(
        "SELECT notes_json FROM hunting_sessions WHERE id = ?"
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    let mut notes: Vec<SessionNote> = serde_json::from_str(&current).unwrap_or_default();
    notes.push(note.clone());

    let notes_json = serde_json::to_string(&notes)?;

    sqlx::query("UPDATE hunting_sessions SET notes_json = ? WHERE id = ?")
        .bind(&notes_json)
        .bind(session_id)
        .execute(pool)
        .await?;

    Ok(note)
}

// ============================================================================
// Retrospective Search Operations
// ============================================================================

/// Create a retrospective search
pub async fn create_retrospective_search(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateSearchRequest,
) -> Result<RetrospectiveSearch> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let ioc_ids_json = request.ioc_ids.as_ref()
        .map(|i| serde_json::to_string(i).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    let ioc_values_json = request.ioc_values.as_ref()
        .map(|i| serde_json::to_string(i).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());

    let sources: Vec<SearchSourceType> = request.sources.as_ref()
        .map(|s| s.iter().map(|src| match src.as_str() {
            "scan_results" => SearchSourceType::ScanResults,
            "siem_logs" => SearchSourceType::SiemLogs,
            "firewall_logs" => SearchSourceType::FirewallLogs,
            "dns_logs" => SearchSourceType::DnsLogs,
            "auth_logs" => SearchSourceType::AuthLogs,
            "network_flows" => SearchSourceType::NetworkFlows,
            "endpoint_logs" => SearchSourceType::EndpointLogs,
            "cloud_logs" => SearchSourceType::CloudLogs,
            _ => SearchSourceType::Custom(src.clone()),
        }).collect())
        .unwrap_or_else(|| vec![SearchSourceType::ScanResults]);

    let sources_json = serde_json::to_string(&sources)?;

    sqlx::query(
        r#"
        INSERT INTO retrospective_searches (id, name, query, ioc_ids_json, ioc_values_json,
                                           time_start, time_end, sources_json, status,
                                           results_count, progress, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, 0, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(&request.name)
    .bind(&request.query)
    .bind(&ioc_ids_json)
    .bind(&ioc_values_json)
    .bind(request.time_start.to_rfc3339())
    .bind(request.time_end.to_rfc3339())
    .bind(&sources_json)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(RetrospectiveSearch {
        id,
        name: request.name.clone(),
        query: request.query.clone(),
        ioc_ids: request.ioc_ids.clone().unwrap_or_default(),
        ioc_values: request.ioc_values.clone().unwrap_or_default(),
        time_start: request.time_start,
        time_end: request.time_end,
        sources,
        status: SearchStatus::Pending,
        results_count: 0,
        user_id: user_id.to_string(),
        created_at: now,
        started_at: None,
        completed_at: None,
        error_message: None,
        progress: 0,
    })
}

/// Get search by ID
pub async fn get_search_by_id(pool: &SqlitePool, id: &str) -> Result<Option<RetrospectiveSearch>> {
    let row = sqlx::query_as::<_, SearchRow>(
        "SELECT * FROM retrospective_searches WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_search()))
}

/// Get user's searches
pub async fn get_user_searches(pool: &SqlitePool, user_id: &str, limit: i32) -> Result<Vec<RetrospectiveSearch>> {
    let rows = sqlx::query_as::<_, SearchRow>(
        "SELECT * FROM retrospective_searches WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_search()).collect())
}

/// Update search status
pub async fn update_search_status(
    pool: &SqlitePool,
    id: &str,
    status: SearchStatus,
    results_count: Option<u32>,
    error_message: Option<String>,
) -> Result<bool> {
    let now = Utc::now();

    let (started_at, completed_at) = match status {
        SearchStatus::Running => (Some(now.to_rfc3339()), None),
        SearchStatus::Completed | SearchStatus::Failed | SearchStatus::Cancelled => {
            (None, Some(now.to_rfc3339()))
        }
        _ => (None, None),
    };

    let result = sqlx::query(
        r#"
        UPDATE retrospective_searches
        SET status = ?, results_count = COALESCE(?, results_count),
            error_message = ?, started_at = COALESCE(?, started_at),
            completed_at = COALESCE(?, completed_at)
        WHERE id = ?
        "#,
    )
    .bind(status.to_string())
    .bind(results_count.map(|c| c as i32))
    .bind(&error_message)
    .bind(&started_at)
    .bind(&completed_at)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Update search progress
pub async fn update_search_progress(pool: &SqlitePool, id: &str, progress: u8) -> Result<bool> {
    let result = sqlx::query("UPDATE retrospective_searches SET progress = ? WHERE id = ?")
        .bind(progress as i32)
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Store search result
pub async fn store_search_result(pool: &SqlitePool, result: &SearchResult) -> Result<()> {
    let context_json = serde_json::to_string(&result.context)?;
    let metadata_json = result.metadata.as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_default());

    sqlx::query(
        r#"
        INSERT INTO retrospective_search_results (id, search_id, matched_ioc, ioc_type,
                                                  source_type, source_id, match_timestamp,
                                                  context_json, severity, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&result.id)
    .bind(&result.search_id)
    .bind(&result.matched_ioc)
    .bind(result.ioc_type.to_string())
    .bind(result.source_type.to_string())
    .bind(&result.source_id)
    .bind(result.match_timestamp.to_rfc3339())
    .bind(&context_json)
    .bind(&result.severity)
    .bind(&metadata_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get search results
pub async fn get_search_results(pool: &SqlitePool, search_id: &str, limit: i32, offset: i32) -> Result<Vec<SearchResult>> {
    let rows = sqlx::query_as::<_, SearchResultRow>(
        "SELECT * FROM retrospective_search_results WHERE search_id = ? ORDER BY match_timestamp DESC LIMIT ? OFFSET ?"
    )
    .bind(search_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_result()).collect())
}

// ============================================================================
// Row Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct IocRow {
    id: String,
    ioc_type: String,
    value: String,
    description: Option<String>,
    source: String,
    status: String,
    severity: String,
    first_seen: String,
    last_seen: String,
    tags: String,
    user_id: String,
    metadata: Option<String>,
    threat_actor: Option<String>,
    mitre_techniques: String,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl IocRow {
    fn into_ioc(self) -> Ioc {
        Ioc {
            id: self.id,
            ioc_type: IocType::from_str(&self.ioc_type).unwrap_or(IocType::Ip),
            value: self.value,
            description: self.description,
            source: IocSource::from_str(&self.source).unwrap_or(IocSource::Manual),
            status: IocStatus::from_str(&self.status).unwrap_or(IocStatus::Active),
            severity: IocSeverity::from_str(&self.severity).unwrap_or(IocSeverity::Medium),
            first_seen: DateTime::parse_from_rfc3339(&self.first_seen)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen: DateTime::parse_from_rfc3339(&self.last_seen)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            tags: serde_json::from_str(&self.tags).unwrap_or_default(),
            user_id: self.user_id,
            metadata: self.metadata.and_then(|m| serde_json::from_str(&m).ok()),
            threat_actor: self.threat_actor,
            mitre_techniques: serde_json::from_str(&self.mitre_techniques).unwrap_or_default(),
            expires_at: self.expires_at.and_then(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct IocMatchRow {
    id: String,
    ioc_id: String,
    source_type: String,
    source_id: String,
    matched_at: String,
    context: Option<String>,
}

impl IocMatchRow {
    fn into_match(self) -> IocMatch {
        IocMatch {
            id: self.id,
            ioc_id: self.ioc_id,
            source_type: self.source_type,
            source_id: self.source_id,
            matched_at: DateTime::parse_from_rfc3339(&self.matched_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            context: self.context.and_then(|c| serde_json::from_str(&c).ok()),
            ioc: None,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DetectionMappingRow {
    id: String,
    detection_name: String,
    detection_query: Option<String>,
    technique_ids: String,
    data_sources: String,
    detection_type: String,
    coverage_level: String,
    notes: Option<String>,
    user_id: String,
    created_at: String,
    #[allow(dead_code)]
    updated_at: String,
}

impl DetectionMappingRow {
    fn into_mapping(self) -> DetectionMapping {
        DetectionMapping {
            id: self.id,
            detection_name: self.detection_name,
            detection_query: self.detection_query,
            technique_ids: serde_json::from_str(&self.technique_ids).unwrap_or_default(),
            data_sources: serde_json::from_str(&self.data_sources).unwrap_or_default(),
            detection_type: self.detection_type,
            coverage_level: CoverageLevel::from_str(&self.coverage_level).unwrap_or(CoverageLevel::Low),
            notes: self.notes,
            user_id: self.user_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct PlaybookRow {
    id: String,
    name: String,
    description: String,
    category: String,
    difficulty: String,
    estimated_duration: Option<String>,
    steps_json: String,
    tags: String,
    mitre_tactics: String,
    mitre_techniques: String,
    is_builtin: i32,
    user_id: Option<String>,
    version: String,
    created_at: String,
    updated_at: String,
}

impl PlaybookRow {
    fn into_playbook(self) -> HuntingPlaybook {
        HuntingPlaybook {
            id: self.id,
            name: self.name,
            description: self.description,
            category: PlaybookCategory::from_str(&self.category).unwrap_or(PlaybookCategory::Custom),
            difficulty: DifficultyLevel::from_str(&self.difficulty).unwrap_or(DifficultyLevel::Intermediate),
            estimated_duration: self.estimated_duration.unwrap_or_else(|| "2-4 hours".to_string()),
            steps: serde_json::from_str(&self.steps_json).unwrap_or_default(),
            tags: serde_json::from_str(&self.tags).unwrap_or_default(),
            mitre_tactics: serde_json::from_str(&self.mitre_tactics).unwrap_or_default(),
            mitre_techniques: serde_json::from_str(&self.mitre_techniques).unwrap_or_default(),
            is_builtin: self.is_builtin != 0,
            user_id: self.user_id,
            version: self.version,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    playbook_id: String,
    status: String,
    current_step: i32,
    step_progress_json: String,
    findings_json: String,
    notes_json: String,
    time_spent_minutes: i32,
    scope: Option<String>,
    hypothesis: Option<String>,
    started_at: String,
    completed_at: Option<String>,
    user_id: String,
}

impl SessionRow {
    fn into_session(self) -> HuntingSession {
        HuntingSession {
            id: self.id,
            playbook_id: self.playbook_id,
            status: SessionStatus::from_str(&self.status).unwrap_or(SessionStatus::Active),
            current_step: self.current_step as u32,
            step_progress: serde_json::from_str(&self.step_progress_json).unwrap_or_default(),
            findings: serde_json::from_str(&self.findings_json).unwrap_or_default(),
            notes: serde_json::from_str(&self.notes_json).unwrap_or_default(),
            time_spent_minutes: self.time_spent_minutes as u32,
            scope: self.scope,
            hypothesis: self.hypothesis,
            started_at: DateTime::parse_from_rfc3339(&self.started_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            completed_at: self.completed_at.and_then(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            user_id: self.user_id,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SearchRow {
    id: String,
    name: String,
    query: Option<String>,
    ioc_ids_json: Option<String>,
    ioc_values_json: Option<String>,
    time_start: String,
    time_end: String,
    sources_json: Option<String>,
    status: String,
    results_count: i32,
    progress: i32,
    error_message: Option<String>,
    user_id: String,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl SearchRow {
    fn into_search(self) -> RetrospectiveSearch {
        RetrospectiveSearch {
            id: self.id,
            name: self.name,
            query: self.query,
            ioc_ids: self.ioc_ids_json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default(),
            ioc_values: self.ioc_values_json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default(),
            time_start: DateTime::parse_from_rfc3339(&self.time_start)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            time_end: DateTime::parse_from_rfc3339(&self.time_end)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            sources: self.sources_json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default(),
            status: SearchStatus::from_str(&self.status).unwrap_or(SearchStatus::Pending),
            results_count: self.results_count as u32,
            progress: self.progress as u8,
            error_message: self.error_message,
            user_id: self.user_id,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            started_at: self.started_at.and_then(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
            completed_at: self.completed_at.and_then(|d| DateTime::parse_from_rfc3339(&d).ok().map(|dt| dt.with_timezone(&Utc))),
        }
    }
}

#[derive(sqlx::FromRow)]
struct SearchResultRow {
    id: String,
    search_id: String,
    matched_ioc: String,
    ioc_type: String,
    source_type: String,
    source_id: String,
    match_timestamp: String,
    context_json: Option<String>,
    severity: String,
    metadata: Option<String>,
}

impl SearchResultRow {
    fn into_result(self) -> SearchResult {
        let context: MatchContext = self.context_json
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or(MatchContext {
                source_ip: None,
                dest_ip: None,
                hostname: None,
                user: None,
                process: None,
                raw_data: None,
                scan_id: None,
                vulnerability_id: None,
                additional_fields: None,
            });

        SearchResult {
            id: self.id,
            search_id: self.search_id,
            matched_ioc: self.matched_ioc,
            ioc_type: IocType::from_str(&self.ioc_type).unwrap_or(IocType::Ip),
            source_type: match self.source_type.as_str() {
                "scan_results" => SearchSourceType::ScanResults,
                "siem_logs" => SearchSourceType::SiemLogs,
                "firewall_logs" => SearchSourceType::FirewallLogs,
                "dns_logs" => SearchSourceType::DnsLogs,
                "auth_logs" => SearchSourceType::AuthLogs,
                "network_flows" => SearchSourceType::NetworkFlows,
                "endpoint_logs" => SearchSourceType::EndpointLogs,
                "cloud_logs" => SearchSourceType::CloudLogs,
                s => SearchSourceType::Custom(s.to_string()),
            },
            source_id: self.source_id,
            match_timestamp: DateTime::parse_from_rfc3339(&self.match_timestamp)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            context,
            severity: self.severity,
            metadata: self.metadata.and_then(|m| serde_json::from_str(&m).ok()),
        }
    }
}
