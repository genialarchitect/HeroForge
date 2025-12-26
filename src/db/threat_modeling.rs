//! Database operations for Threat Modeling (Yellow Team)
//!
//! This module provides persistence for:
//! - Threat models and their metadata
//! - System components
//! - Data flows
//! - Trust boundaries
//! - STRIDE threats
//! - Mitigations

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::yellow_team::{
    ThreatModel, SystemComponent, ArchComponentType, TrustLevel,
    DataFlow, DataClassification, TrustBoundary, BoundaryType,
    StrideTheat, StrideCategory, Mitigation, ControlType, ImplementationStatus,
    ThreatModelStatus, ThreatStatus, Likelihood, Impact, RiskRating,
    CreateThreatModelRequest, UpdateThreatModelRequest,
    AddComponentRequest, AddDataFlowRequest, AddTrustBoundaryRequest, AddMitigationRequest,
    UpdateThreatStatusRequest, ThreatModelSummary,
};

// ============================================================================
// Database Initialization
// ============================================================================

/// Initialize threat modeling database tables
pub async fn init_threat_modeling_tables(pool: &SqlitePool) -> Result<()> {
    // Threat Models table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_models (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            org_id TEXT,
            name TEXT NOT NULL,
            system_description TEXT NOT NULL,
            risk_score REAL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'draft',
            version INTEGER DEFAULT 1,
            tags TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // System Components table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_model_components (
            id TEXT PRIMARY KEY,
            threat_model_id TEXT NOT NULL,
            name TEXT NOT NULL,
            component_type TEXT NOT NULL,
            description TEXT,
            trust_level TEXT NOT NULL DEFAULT 'semi_trusted',
            technologies TEXT,
            external INTEGER DEFAULT 0,
            position_x REAL,
            position_y REAL,
            metadata TEXT,
            FOREIGN KEY (threat_model_id) REFERENCES threat_models(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Data Flows table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_model_data_flows (
            id TEXT PRIMARY KEY,
            threat_model_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            source_id TEXT NOT NULL,
            destination_id TEXT NOT NULL,
            data_classification TEXT NOT NULL DEFAULT 'internal',
            protocol TEXT,
            port INTEGER,
            encrypted INTEGER DEFAULT 0,
            authenticated INTEGER DEFAULT 0,
            bidirectional INTEGER DEFAULT 0,
            crosses_trust_boundary INTEGER DEFAULT 0,
            data_types TEXT,
            FOREIGN KEY (threat_model_id) REFERENCES threat_models(id) ON DELETE CASCADE,
            FOREIGN KEY (source_id) REFERENCES threat_model_components(id),
            FOREIGN KEY (destination_id) REFERENCES threat_model_components(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Trust Boundaries table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_model_trust_boundaries (
            id TEXT PRIMARY KEY,
            threat_model_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            boundary_type TEXT NOT NULL DEFAULT 'network',
            components TEXT,
            color TEXT,
            position_x REAL,
            position_y REAL,
            width REAL,
            height REAL,
            FOREIGN KEY (threat_model_id) REFERENCES threat_models(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // STRIDE Threats table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_model_threats (
            id TEXT PRIMARY KEY,
            threat_model_id TEXT NOT NULL,
            category TEXT NOT NULL,
            affected_component_id TEXT NOT NULL,
            affected_dataflow_id TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            attack_scenario TEXT NOT NULL,
            prerequisites TEXT,
            likelihood TEXT NOT NULL DEFAULT 'medium',
            impact TEXT NOT NULL DEFAULT 'moderate',
            risk_rating TEXT NOT NULL DEFAULT 'medium',
            mitigations TEXT,
            status TEXT NOT NULL DEFAULT 'identified',
            priority INTEGER DEFAULT 0,
            cwe_ids TEXT,
            capec_ids TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (threat_model_id) REFERENCES threat_models(id) ON DELETE CASCADE,
            FOREIGN KEY (affected_component_id) REFERENCES threat_model_components(id)
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Mitigations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_model_mitigations (
            id TEXT PRIMARY KEY,
            threat_model_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            control_type TEXT NOT NULL DEFAULT 'preventive',
            implementation_status TEXT NOT NULL DEFAULT 'not_started',
            implementation_notes TEXT,
            linked_controls TEXT,
            effort_estimate TEXT,
            cost_estimate TEXT,
            effectiveness INTEGER,
            owner TEXT,
            due_date TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (threat_model_id) REFERENCES threat_models(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Threat-Mitigation mapping table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS threat_mitigation_mapping (
            threat_id TEXT NOT NULL,
            mitigation_id TEXT NOT NULL,
            PRIMARY KEY (threat_id, mitigation_id),
            FOREIGN KEY (threat_id) REFERENCES threat_model_threats(id) ON DELETE CASCADE,
            FOREIGN KEY (mitigation_id) REFERENCES threat_model_mitigations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_models_user_id ON threat_models(user_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_models_org_id ON threat_models(org_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_threat_models_status ON threat_models(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_components_model_id ON threat_model_components(threat_model_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_data_flows_model_id ON threat_model_data_flows(threat_model_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_boundaries_model_id ON threat_model_trust_boundaries(threat_model_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_threats_model_id ON threat_model_threats(threat_model_id)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_threats_category ON threat_model_threats(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_threats_status ON threat_model_threats(status)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tm_mitigations_model_id ON threat_model_mitigations(threat_model_id)")
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Threat Model CRUD Operations
// ============================================================================

/// Create a new threat model
pub async fn create_threat_model(
    pool: &SqlitePool,
    user_id: &str,
    request: &CreateThreatModelRequest,
) -> Result<ThreatModel> {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t))
        .transpose()?;

    sqlx::query(
        r#"
        INSERT INTO threat_models (
            id, user_id, org_id, name, system_description,
            risk_score, status, version, tags, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(user_id)
    .bind(request.org_id.map(|id| id.to_string()))
    .bind(&request.name)
    .bind(&request.system_description)
    .bind(0.0f64)
    .bind("draft")
    .bind(1i32)
    .bind(&tags_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(ThreatModel {
        id,
        user_id: Uuid::parse_str(user_id)?,
        org_id: request.org_id,
        name: request.name.clone(),
        system_description: request.system_description.clone(),
        components: Vec::new(),
        data_flows: Vec::new(),
        trust_boundaries: Vec::new(),
        threats: Vec::new(),
        mitigations: Vec::new(),
        risk_score: 0.0,
        status: ThreatModelStatus::Draft,
        version: 1,
        created_at: now,
        updated_at: now,
        created_by: None,
        tags: request.tags.clone().unwrap_or_default(),
    })
}

/// Get all threat models for a user
pub async fn get_user_threat_models(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<ThreatModelSummary>> {
    let rows = sqlx::query_as::<_, ThreatModelRow>(
        r#"
        SELECT
            tm.id, tm.user_id, tm.org_id, tm.name, tm.system_description,
            tm.risk_score, tm.status, tm.version, tm.tags,
            tm.created_by, tm.created_at, tm.updated_at,
            (SELECT COUNT(*) FROM threat_model_components WHERE threat_model_id = tm.id) as component_count,
            (SELECT COUNT(*) FROM threat_model_data_flows WHERE threat_model_id = tm.id) as data_flow_count,
            (SELECT COUNT(*) FROM threat_model_trust_boundaries WHERE threat_model_id = tm.id) as boundary_count,
            (SELECT COUNT(*) FROM threat_model_threats WHERE threat_model_id = tm.id) as threat_count,
            (SELECT COUNT(*) FROM threat_model_mitigations WHERE threat_model_id = tm.id) as mitigation_count
        FROM threat_models tm
        WHERE tm.user_id = ?
        ORDER BY tm.updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut summaries = Vec::new();
    for row in rows {
        summaries.push(row_to_summary(row)?);
    }

    Ok(summaries)
}

/// Get a threat model by ID with all related data
pub async fn get_threat_model_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<ThreatModel>> {
    // Get main threat model data
    let row = sqlx::query_as::<_, ThreatModelRow>(
        r#"
        SELECT
            tm.id, tm.user_id, tm.org_id, tm.name, tm.system_description,
            tm.risk_score, tm.status, tm.version, tm.tags,
            tm.created_by, tm.created_at, tm.updated_at,
            0 as component_count, 0 as data_flow_count, 0 as boundary_count,
            0 as threat_count, 0 as mitigation_count
        FROM threat_models tm
        WHERE tm.id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };

    // Get components
    let components = get_components(pool, id).await?;

    // Get data flows
    let data_flows = get_data_flows(pool, id).await?;

    // Get trust boundaries
    let trust_boundaries = get_trust_boundaries(pool, id).await?;

    // Get threats
    let threats = get_threats(pool, id).await?;

    // Get mitigations
    let mitigations = get_mitigations(pool, id).await?;

    // Build the full model
    let tags: Vec<String> = row.tags
        .as_ref()
        .and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or_default();

    Ok(Some(ThreatModel {
        id: Uuid::parse_str(&row.id)?,
        user_id: Uuid::parse_str(&row.user_id)?,
        org_id: row.org_id.as_ref().and_then(|id| Uuid::parse_str(id).ok()),
        name: row.name,
        system_description: row.system_description,
        components,
        data_flows,
        trust_boundaries,
        threats,
        mitigations,
        risk_score: row.risk_score,
        status: ThreatModelStatus::from_str(&row.status),
        version: row.version as u32,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&Utc),
        created_by: row.created_by,
        tags,
    }))
}

/// Update a threat model
pub async fn update_threat_model(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateThreatModelRequest,
) -> Result<()> {
    let now = Utc::now();

    // Get current version
    let current: Option<(i32,)> = sqlx::query_as(
        "SELECT version FROM threat_models WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let new_version = current.map(|c| c.0 + 1).unwrap_or(1);

    let tags_json = request.tags.as_ref()
        .map(|t| serde_json::to_string(t))
        .transpose()?;

    let status = request.status.as_ref().map(|s| s.to_string());

    sqlx::query(
        r#"
        UPDATE threat_models
        SET name = COALESCE(?, name),
            system_description = COALESCE(?, system_description),
            status = COALESCE(?, status),
            tags = COALESCE(?, tags),
            version = ?,
            updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(&request.name)
    .bind(&request.system_description)
    .bind(&status)
    .bind(&tags_json)
    .bind(new_version)
    .bind(now.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a threat model
pub async fn delete_threat_model(pool: &SqlitePool, id: &str) -> Result<()> {
    // Cascade delete handles related data
    sqlx::query("DELETE FROM threat_models WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Update the risk score of a threat model
pub async fn update_risk_score(pool: &SqlitePool, id: &str, score: f64) -> Result<()> {
    sqlx::query(
        "UPDATE threat_models SET risk_score = ?, updated_at = ? WHERE id = ?"
    )
    .bind(score)
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================================
// Component Operations
// ============================================================================

/// Add a component to a threat model
pub async fn add_component(
    pool: &SqlitePool,
    threat_model_id: &str,
    request: &AddComponentRequest,
) -> Result<SystemComponent> {
    let id = Uuid::new_v4();
    let technologies_json = request.technologies.as_ref()
        .map(|t| serde_json::to_string(t))
        .transpose()?;
    let metadata_json = request.metadata.as_ref()
        .map(|m| serde_json::to_string(m))
        .transpose()?;

    let trust_level = request.trust_level.unwrap_or_default();
    let component_type = request.component_type;

    let data_classification = request.data_classification.unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO threat_model_components (
            id, threat_model_id, name, component_type, description,
            trust_level, data_classification, technologies, external, position_x, position_y, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(threat_model_id)
    .bind(&request.name)
    .bind(component_type.to_string())
    .bind(&request.description)
    .bind(trust_level.to_string())
    .bind(data_classification.to_string())
    .bind(&technologies_json)
    .bind(request.external.unwrap_or(false) as i32)
    .bind(request.position_x)
    .bind(request.position_y)
    .bind(&metadata_json)
    .execute(pool)
    .await?;

    // Update threat model timestamp
    update_model_timestamp(pool, threat_model_id).await?;

    Ok(SystemComponent {
        id,
        threat_model_id: Uuid::parse_str(threat_model_id)?,
        name: request.name.clone(),
        component_type,
        description: request.description.clone(),
        trust_level,
        data_classification: request.data_classification.unwrap_or_default(),
        technologies: request.technologies.clone().unwrap_or_default(),
        external: request.external.unwrap_or(false),
        position_x: request.position_x,
        position_y: request.position_y,
        metadata: request.metadata.clone().unwrap_or_default(),
    })
}

/// Get all components for a threat model
async fn get_components(pool: &SqlitePool, threat_model_id: &str) -> Result<Vec<SystemComponent>> {
    let rows = sqlx::query_as::<_, ComponentRow>(
        r#"
        SELECT id, threat_model_id, name, component_type, description,
               trust_level, data_classification, technologies, external, position_x, position_y, metadata
        FROM threat_model_components
        WHERE threat_model_id = ?
        "#,
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Delete a component
pub async fn delete_component(pool: &SqlitePool, id: &str) -> Result<()> {
    // Get threat model ID first for timestamp update
    let model_id: Option<(String,)> = sqlx::query_as(
        "SELECT threat_model_id FROM threat_model_components WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM threat_model_components WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    if let Some((model_id,)) = model_id {
        update_model_timestamp(pool, &model_id).await?;
    }

    Ok(())
}

// ============================================================================
// Data Flow Operations
// ============================================================================

/// Add a data flow to a threat model
pub async fn add_data_flow(
    pool: &SqlitePool,
    threat_model_id: &str,
    request: &AddDataFlowRequest,
) -> Result<DataFlow> {
    let id = Uuid::new_v4();
    let data_types_json = request.data_types.as_ref()
        .map(|d| serde_json::to_string(d))
        .transpose()?;

    let classification = request.data_classification.unwrap_or_default();

    // Check if flow crosses trust boundary
    let crosses_boundary = check_crosses_trust_boundary(
        pool, threat_model_id, &request.source_id.to_string(), &request.destination_id.to_string()
    ).await?;

    sqlx::query(
        r#"
        INSERT INTO threat_model_data_flows (
            id, threat_model_id, name, description, source_id, destination_id,
            data_classification, protocol, port, encrypted, authenticated,
            bidirectional, crosses_trust_boundary, data_types
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(threat_model_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.source_id.to_string())
    .bind(request.destination_id.to_string())
    .bind(classification.to_string())
    .bind(&request.protocol)
    .bind(request.port.map(|p| p as i32))
    .bind(request.encrypted.unwrap_or(false) as i32)
    .bind(request.authenticated.unwrap_or(false) as i32)
    .bind(request.bidirectional.unwrap_or(false) as i32)
    .bind(crosses_boundary as i32)
    .bind(&data_types_json)
    .execute(pool)
    .await?;

    update_model_timestamp(pool, threat_model_id).await?;

    Ok(DataFlow {
        id,
        threat_model_id: Uuid::parse_str(threat_model_id)?,
        name: request.name.clone(),
        description: request.description.clone(),
        source_id: request.source_id,
        destination_id: request.destination_id,
        data_classification: classification,
        protocol: request.protocol.clone(),
        port: request.port,
        encrypted: request.encrypted.unwrap_or(false),
        authenticated: request.authenticated.unwrap_or(false),
        bidirectional: request.bidirectional.unwrap_or(false),
        crosses_trust_boundary: crosses_boundary,
        data_types: request.data_types.clone().unwrap_or_default(),
    })
}

/// Check if a data flow crosses a trust boundary
async fn check_crosses_trust_boundary(
    pool: &SqlitePool,
    threat_model_id: &str,
    source_id: &str,
    dest_id: &str,
) -> Result<bool> {
    // Get all trust boundaries
    let boundaries = sqlx::query_as::<_, (String,)>(
        "SELECT components FROM threat_model_trust_boundaries WHERE threat_model_id = ?"
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    for (components_json,) in boundaries {
        let components: Vec<String> = serde_json::from_str(&components_json).unwrap_or_default();
        let source_in = components.contains(&source_id.to_string());
        let dest_in = components.contains(&dest_id.to_string());

        // If one is in and one is out, it crosses
        if source_in != dest_in {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Get all data flows for a threat model
async fn get_data_flows(pool: &SqlitePool, threat_model_id: &str) -> Result<Vec<DataFlow>> {
    let rows = sqlx::query_as::<_, DataFlowRow>(
        r#"
        SELECT id, threat_model_id, name, description, source_id, destination_id,
               data_classification, protocol, port, encrypted, authenticated,
               bidirectional, crosses_trust_boundary, data_types
        FROM threat_model_data_flows
        WHERE threat_model_id = ?
        "#,
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Delete a data flow
pub async fn delete_data_flow(pool: &SqlitePool, id: &str) -> Result<()> {
    let model_id: Option<(String,)> = sqlx::query_as(
        "SELECT threat_model_id FROM threat_model_data_flows WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM threat_model_data_flows WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    if let Some((model_id,)) = model_id {
        update_model_timestamp(pool, &model_id).await?;
    }

    Ok(())
}

// ============================================================================
// Trust Boundary Operations
// ============================================================================

/// Add a trust boundary to a threat model
pub async fn add_trust_boundary(
    pool: &SqlitePool,
    threat_model_id: &str,
    request: &AddTrustBoundaryRequest,
) -> Result<TrustBoundary> {
    let id = Uuid::new_v4();
    let components_json = request.components.as_ref()
        .map(|c| serde_json::to_string(&c.iter().map(|u| u.to_string()).collect::<Vec<_>>()))
        .transpose()?;

    let boundary_type = request.boundary_type.unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO threat_model_trust_boundaries (
            id, threat_model_id, name, description, boundary_type,
            components, color, position_x, position_y, width, height
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(threat_model_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(boundary_type.to_string())
    .bind(&components_json)
    .bind(&request.color)
    .bind(request.position_x)
    .bind(request.position_y)
    .bind(request.width)
    .bind(request.height)
    .execute(pool)
    .await?;

    update_model_timestamp(pool, threat_model_id).await?;

    Ok(TrustBoundary {
        id,
        threat_model_id: Uuid::parse_str(threat_model_id)?,
        name: request.name.clone(),
        description: request.description.clone(),
        boundary_type,
        components: request.components.clone().unwrap_or_default(),
        color: request.color.clone(),
        position_x: request.position_x,
        position_y: request.position_y,
        width: request.width,
        height: request.height,
    })
}

/// Get all trust boundaries for a threat model
async fn get_trust_boundaries(pool: &SqlitePool, threat_model_id: &str) -> Result<Vec<TrustBoundary>> {
    let rows = sqlx::query_as::<_, TrustBoundaryRow>(
        r#"
        SELECT id, threat_model_id, name, description, boundary_type,
               components, color, position_x, position_y, width, height
        FROM threat_model_trust_boundaries
        WHERE threat_model_id = ?
        "#,
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Delete a trust boundary
pub async fn delete_trust_boundary(pool: &SqlitePool, id: &str) -> Result<()> {
    let model_id: Option<(String,)> = sqlx::query_as(
        "SELECT threat_model_id FROM threat_model_trust_boundaries WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM threat_model_trust_boundaries WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    if let Some((model_id,)) = model_id {
        update_model_timestamp(pool, &model_id).await?;
    }

    Ok(())
}

// ============================================================================
// Threat Operations
// ============================================================================

/// Save a generated threat
pub async fn save_threat(
    pool: &SqlitePool,
    threat: &StrideTheat,
) -> Result<()> {
    let prerequisites_json = serde_json::to_string(&threat.prerequisites)?;
    let mitigations_json = serde_json::to_string(
        &threat.mitigations.iter().map(|u| u.to_string()).collect::<Vec<_>>()
    )?;
    let cwe_json = serde_json::to_string(&threat.cwe_ids)?;
    let capec_json = serde_json::to_string(&threat.capec_ids)?;

    sqlx::query(
        r#"
        INSERT INTO threat_model_threats (
            id, threat_model_id, category, affected_component_id, affected_dataflow_id,
            title, description, attack_scenario, prerequisites, likelihood, impact,
            risk_rating, mitigations, status, priority, cwe_ids, capec_ids, notes,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(threat.id.to_string())
    .bind(threat.threat_model_id.to_string())
    .bind(threat.category.to_string())
    .bind(threat.affected_component_id.to_string())
    .bind(threat.affected_dataflow_id.map(|id| id.to_string()))
    .bind(&threat.title)
    .bind(&threat.description)
    .bind(&threat.attack_scenario)
    .bind(&prerequisites_json)
    .bind(threat.likelihood.to_string())
    .bind(threat.impact.to_string())
    .bind(threat.risk_rating.to_string())
    .bind(&mitigations_json)
    .bind(threat.status.to_string())
    .bind(threat.priority as i32)
    .bind(&cwe_json)
    .bind(&capec_json)
    .bind(&threat.notes)
    .bind(threat.created_at.to_rfc3339())
    .bind(threat.updated_at.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all threats for a threat model
async fn get_threats(pool: &SqlitePool, threat_model_id: &str) -> Result<Vec<StrideTheat>> {
    let rows = sqlx::query_as::<_, ThreatRow>(
        r#"
        SELECT id, threat_model_id, category, affected_component_id, affected_dataflow_id,
               title, description, attack_scenario, prerequisites, likelihood, impact,
               risk_rating, mitigations, status, priority, cwe_ids, capec_ids, notes,
               created_at, updated_at
        FROM threat_model_threats
        WHERE threat_model_id = ?
        ORDER BY priority DESC, created_at DESC
        "#,
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Update threat status
pub async fn update_threat_status(
    pool: &SqlitePool,
    id: &str,
    request: &UpdateThreatStatusRequest,
) -> Result<()> {
    let now = Utc::now();
    let mitigations_json = request.mitigation_ids.as_ref()
        .map(|ids| serde_json::to_string(&ids.iter().map(|u| u.to_string()).collect::<Vec<_>>()))
        .transpose()?;

    sqlx::query(
        r#"
        UPDATE threat_model_threats
        SET status = ?, mitigations = COALESCE(?, mitigations), notes = COALESCE(?, notes), updated_at = ?
        WHERE id = ?
        "#,
    )
    .bind(request.status.to_string())
    .bind(&mitigations_json)
    .bind(&request.notes)
    .bind(now.to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete all threats for a threat model (used before re-analysis)
pub async fn delete_threats(pool: &SqlitePool, threat_model_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM threat_model_threats WHERE threat_model_id = ?")
        .bind(threat_model_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Add a manual threat to a threat model
pub async fn add_threat(
    pool: &SqlitePool,
    threat_model_id: &str,
    request: &crate::yellow_team::AddThreatRequest,
) -> Result<StrideTheat> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    let likelihood = request.likelihood.unwrap_or_default();
    let impact = request.impact.unwrap_or_default();
    let risk_rating = RiskRating::calculate(likelihood, impact);

    let prerequisites_json = request.prerequisites.as_ref()
        .map(|p| serde_json::to_string(p))
        .transpose()?
        .unwrap_or_else(|| "[]".to_string());
    let mitigations_json = request.mitigations.as_ref()
        .map(|m| serde_json::to_string(m))
        .transpose()?
        .unwrap_or_else(|| "[]".to_string());
    let cwe_json = request.cwe_ids.as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()?
        .unwrap_or_else(|| "[]".to_string());
    let capec_json = request.capec_ids.as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()?
        .unwrap_or_else(|| "[]".to_string());

    let attack_scenario = request.attack_scenario.clone()
        .unwrap_or_else(|| "Manual threat - attack scenario not specified".to_string());

    sqlx::query(
        r#"
        INSERT INTO threat_model_threats (
            id, threat_model_id, category, affected_component_id, affected_dataflow_id,
            title, description, attack_scenario, prerequisites, likelihood, impact,
            risk_rating, mitigations, status, priority, cwe_ids, capec_ids, notes,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(threat_model_id)
    .bind(request.stride_category.to_string())
    .bind(request.affected_component_id.to_string())
    .bind(request.affected_dataflow_id.map(|id| id.to_string()))
    .bind(&request.title)
    .bind(&request.description)
    .bind(&attack_scenario)
    .bind(&prerequisites_json)
    .bind(likelihood.to_string())
    .bind(impact.to_string())
    .bind(risk_rating.to_string())
    .bind(&mitigations_json)
    .bind(ThreatStatus::Identified.to_string())
    .bind(risk_rating.score() as i32)
    .bind(&cwe_json)
    .bind(&capec_json)
    .bind(&request.notes)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    // Update threat model timestamp
    update_model_timestamp(pool, threat_model_id).await?;

    Ok(StrideTheat {
        id,
        threat_model_id: Uuid::parse_str(threat_model_id)?,
        category: request.stride_category,
        affected_component_id: request.affected_component_id,
        affected_dataflow_id: request.affected_dataflow_id,
        title: request.title.clone(),
        description: request.description.clone(),
        attack_scenario,
        prerequisites: request.prerequisites.clone().unwrap_or_default(),
        likelihood,
        impact,
        risk_rating,
        mitigations: Vec::new(),
        status: ThreatStatus::Identified,
        priority: risk_rating.score(),
        cwe_ids: request.cwe_ids.clone().unwrap_or_default(),
        capec_ids: request.capec_ids.clone().unwrap_or_default(),
        notes: request.notes.clone(),
        created_at: now,
        updated_at: now,
    })
}

/// Update an existing threat
pub async fn update_threat(
    pool: &SqlitePool,
    threat_id: &str,
    request: &crate::yellow_team::UpdateThreatRequest,
) -> Result<()> {
    let now = Utc::now();

    // Calculate new risk rating if likelihood or impact changed
    let risk_update = if request.likelihood.is_some() || request.impact.is_some() {
        // Get current values
        let current: Option<(String, String)> = sqlx::query_as(
            "SELECT likelihood, impact FROM threat_model_threats WHERE id = ?"
        )
        .bind(threat_id)
        .fetch_optional(pool)
        .await?;

        if let Some((curr_likelihood, curr_impact)) = current {
            let likelihood = request.likelihood.unwrap_or_else(|| Likelihood::from_str(&curr_likelihood));
            let impact = request.impact.unwrap_or_else(|| Impact::from_str(&curr_impact));
            let risk_rating = RiskRating::calculate(likelihood, impact);
            Some((likelihood.to_string(), impact.to_string(), risk_rating.to_string(), risk_rating.score() as i32))
        } else {
            None
        }
    } else {
        None
    };

    let prerequisites_json = request.prerequisites.as_ref()
        .map(|p| serde_json::to_string(p))
        .transpose()?;
    let mitigations_json = request.mitigations.as_ref()
        .map(|m| serde_json::to_string(m))
        .transpose()?;
    let cwe_json = request.cwe_ids.as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()?;
    let capec_json = request.capec_ids.as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()?;

    if let Some((likelihood, impact, risk_rating, priority)) = risk_update {
        sqlx::query(
            r#"
            UPDATE threat_model_threats
            SET title = COALESCE(?, title),
                description = COALESCE(?, description),
                attack_scenario = COALESCE(?, attack_scenario),
                prerequisites = COALESCE(?, prerequisites),
                likelihood = ?,
                impact = ?,
                risk_rating = ?,
                priority = ?,
                status = COALESCE(?, status),
                mitigations = COALESCE(?, mitigations),
                cwe_ids = COALESCE(?, cwe_ids),
                capec_ids = COALESCE(?, capec_ids),
                notes = COALESCE(?, notes),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.attack_scenario)
        .bind(&prerequisites_json)
        .bind(&likelihood)
        .bind(&impact)
        .bind(&risk_rating)
        .bind(priority)
        .bind(request.status.as_ref().map(|s| s.to_string()))
        .bind(&mitigations_json)
        .bind(&cwe_json)
        .bind(&capec_json)
        .bind(&request.notes)
        .bind(now.to_rfc3339())
        .bind(threat_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            r#"
            UPDATE threat_model_threats
            SET title = COALESCE(?, title),
                description = COALESCE(?, description),
                attack_scenario = COALESCE(?, attack_scenario),
                prerequisites = COALESCE(?, prerequisites),
                status = COALESCE(?, status),
                mitigations = COALESCE(?, mitigations),
                cwe_ids = COALESCE(?, cwe_ids),
                capec_ids = COALESCE(?, capec_ids),
                notes = COALESCE(?, notes),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&request.title)
        .bind(&request.description)
        .bind(&request.attack_scenario)
        .bind(&prerequisites_json)
        .bind(request.status.as_ref().map(|s| s.to_string()))
        .bind(&mitigations_json)
        .bind(&cwe_json)
        .bind(&capec_json)
        .bind(&request.notes)
        .bind(now.to_rfc3339())
        .bind(threat_id)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Get a single threat by ID
pub async fn get_threat_by_id(pool: &SqlitePool, id: &str) -> Result<Option<StrideTheat>> {
    let row = sqlx::query_as::<_, ThreatRow>(
        r#"
        SELECT id, threat_model_id, category, affected_component_id, affected_dataflow_id,
               title, description, attack_scenario, prerequisites, likelihood, impact,
               risk_rating, mitigations, status, priority, cwe_ids, capec_ids, notes,
               created_at, updated_at
        FROM threat_model_threats
        WHERE id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(Some(r.try_into()?)),
        None => Ok(None),
    }
}

/// Delete a single threat
pub async fn delete_threat(pool: &SqlitePool, id: &str) -> Result<()> {
    let model_id: Option<(String,)> = sqlx::query_as(
        "SELECT threat_model_id FROM threat_model_threats WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    sqlx::query("DELETE FROM threat_model_threats WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    if let Some((model_id,)) = model_id {
        update_model_timestamp(pool, &model_id).await?;
    }

    Ok(())
}

// ============================================================================
// Mitigation Operations
// ============================================================================

/// Add a mitigation
pub async fn add_mitigation(
    pool: &SqlitePool,
    threat_model_id: &str,
    request: &AddMitigationRequest,
) -> Result<Mitigation> {
    let id = Uuid::new_v4();
    let now = Utc::now();
    let linked_controls_json = request.linked_controls.as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()?;

    let control_type = request.control_type.unwrap_or_default();
    let impl_status = request.implementation_status.unwrap_or_default();

    sqlx::query(
        r#"
        INSERT INTO threat_model_mitigations (
            id, threat_model_id, title, description, control_type,
            implementation_status, implementation_notes, linked_controls,
            effort_estimate, cost_estimate, effectiveness, owner, due_date,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(id.to_string())
    .bind(threat_model_id)
    .bind(&request.title)
    .bind(&request.description)
    .bind(control_type.to_string())
    .bind(impl_status.to_string())
    .bind(&request.implementation_notes)
    .bind(&linked_controls_json)
    .bind(&request.effort_estimate)
    .bind(&request.cost_estimate)
    .bind(request.effectiveness.map(|e| e as i32))
    .bind(&request.owner)
    .bind(request.due_date.map(|d| d.to_rfc3339()))
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    update_model_timestamp(pool, threat_model_id).await?;

    Ok(Mitigation {
        id,
        threat_model_id: Uuid::parse_str(threat_model_id)?,
        title: request.title.clone(),
        description: request.description.clone(),
        control_type,
        implementation_status: impl_status,
        implementation_notes: request.implementation_notes.clone(),
        linked_controls: request.linked_controls.clone().unwrap_or_default(),
        effort_estimate: request.effort_estimate.clone(),
        cost_estimate: request.cost_estimate.clone(),
        effectiveness: request.effectiveness,
        owner: request.owner.clone(),
        due_date: request.due_date,
        created_at: now,
        updated_at: now,
    })
}

/// Get all mitigations for a threat model
async fn get_mitigations(pool: &SqlitePool, threat_model_id: &str) -> Result<Vec<Mitigation>> {
    let rows = sqlx::query_as::<_, MitigationRow>(
        r#"
        SELECT id, threat_model_id, title, description, control_type,
               implementation_status, implementation_notes, linked_controls,
               effort_estimate, cost_estimate, effectiveness, owner, due_date,
               created_at, updated_at
        FROM threat_model_mitigations
        WHERE threat_model_id = ?
        "#,
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.try_into()).collect()
}

/// Delete a mitigation
pub async fn delete_mitigation(pool: &SqlitePool, id: &str) -> Result<()> {
    let model_id: Option<(String,)> = sqlx::query_as(
        "SELECT threat_model_id FROM threat_model_mitigations WHERE id = ?"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    // Remove from mapping table first
    sqlx::query("DELETE FROM threat_mitigation_mapping WHERE mitigation_id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM threat_model_mitigations WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    if let Some((model_id,)) = model_id {
        update_model_timestamp(pool, &model_id).await?;
    }

    Ok(())
}

// ============================================================================
// Statistics & Analytics
// ============================================================================

/// Get threat statistics for a threat model
pub async fn get_threat_statistics(
    pool: &SqlitePool,
    threat_model_id: &str,
) -> Result<HashMap<String, usize>> {
    let mut stats = HashMap::new();

    // By category
    let by_category = sqlx::query_as::<_, (String, i64)>(
        "SELECT category, COUNT(*) FROM threat_model_threats WHERE threat_model_id = ? GROUP BY category"
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    for (cat, count) in by_category {
        stats.insert(format!("category_{}", cat), count as usize);
    }

    // By status
    let by_status = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*) FROM threat_model_threats WHERE threat_model_id = ? GROUP BY status"
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    for (status, count) in by_status {
        stats.insert(format!("status_{}", status), count as usize);
    }

    // By risk rating
    let by_risk = sqlx::query_as::<_, (String, i64)>(
        "SELECT risk_rating, COUNT(*) FROM threat_model_threats WHERE threat_model_id = ? GROUP BY risk_rating"
    )
    .bind(threat_model_id)
    .fetch_all(pool)
    .await?;

    for (risk, count) in by_risk {
        stats.insert(format!("risk_{}", risk), count as usize);
    }

    Ok(stats)
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn update_model_timestamp(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query(
        "UPDATE threat_models SET updated_at = ? WHERE id = ?"
    )
    .bind(Utc::now().to_rfc3339())
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

fn row_to_summary(row: ThreatModelRow) -> Result<ThreatModelSummary> {
    Ok(ThreatModelSummary {
        id: row.id,
        name: row.name,
        status: ThreatModelStatus::from_str(&row.status),
        component_count: row.component_count as u32,
        data_flow_count: row.data_flow_count as u32,
        trust_boundary_count: row.boundary_count as u32,
        threat_count: row.threat_count as u32,
        open_threat_count: 0, // Would need separate query
        mitigation_count: row.mitigation_count as u32,
        risk_score: row.risk_score,
        threats_by_status: HashMap::new(), // Would need separate query
        threats_by_category: HashMap::new(),
        created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&Utc),
    })
}

// ============================================================================
// Row Types for SQLx
// ============================================================================

#[derive(sqlx::FromRow)]
struct ThreatModelRow {
    id: String,
    user_id: String,
    org_id: Option<String>,
    name: String,
    system_description: String,
    risk_score: f64,
    status: String,
    version: i32,
    tags: Option<String>,
    created_by: Option<String>,
    created_at: String,
    updated_at: String,
    component_count: i64,
    data_flow_count: i64,
    boundary_count: i64,
    threat_count: i64,
    mitigation_count: i64,
}

#[derive(sqlx::FromRow)]
struct ComponentRow {
    id: String,
    threat_model_id: String,
    name: String,
    component_type: String,
    description: Option<String>,
    trust_level: String,
    data_classification: String,
    technologies: Option<String>,
    external: i32,
    position_x: Option<f64>,
    position_y: Option<f64>,
    metadata: Option<String>,
}

impl TryFrom<ComponentRow> for SystemComponent {
    type Error = anyhow::Error;

    fn try_from(row: ComponentRow) -> Result<Self> {
        let technologies: Vec<String> = row.technologies
            .as_ref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or_default();
        let metadata: HashMap<String, String> = row.metadata
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        Ok(SystemComponent {
            id: Uuid::parse_str(&row.id)?,
            threat_model_id: Uuid::parse_str(&row.threat_model_id)?,
            name: row.name,
            component_type: ArchComponentType::from_str(&row.component_type),
            description: row.description,
            trust_level: TrustLevel::from_str(&row.trust_level),
            data_classification: DataClassification::from_str(&row.data_classification),
            technologies,
            external: row.external != 0,
            position_x: row.position_x,
            position_y: row.position_y,
            metadata,
        })
    }
}

#[derive(sqlx::FromRow)]
struct DataFlowRow {
    id: String,
    threat_model_id: String,
    name: String,
    description: Option<String>,
    source_id: String,
    destination_id: String,
    data_classification: String,
    protocol: Option<String>,
    port: Option<i32>,
    encrypted: i32,
    authenticated: i32,
    bidirectional: i32,
    crosses_trust_boundary: i32,
    data_types: Option<String>,
}

impl TryFrom<DataFlowRow> for DataFlow {
    type Error = anyhow::Error;

    fn try_from(row: DataFlowRow) -> Result<Self> {
        let data_types: Vec<String> = row.data_types
            .as_ref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or_default();

        Ok(DataFlow {
            id: Uuid::parse_str(&row.id)?,
            threat_model_id: Uuid::parse_str(&row.threat_model_id)?,
            name: row.name,
            description: row.description,
            source_id: Uuid::parse_str(&row.source_id)?,
            destination_id: Uuid::parse_str(&row.destination_id)?,
            data_classification: DataClassification::from_str(&row.data_classification),
            protocol: row.protocol,
            port: row.port.map(|p| p as u16),
            encrypted: row.encrypted != 0,
            authenticated: row.authenticated != 0,
            bidirectional: row.bidirectional != 0,
            crosses_trust_boundary: row.crosses_trust_boundary != 0,
            data_types,
        })
    }
}

#[derive(sqlx::FromRow)]
struct TrustBoundaryRow {
    id: String,
    threat_model_id: String,
    name: String,
    description: Option<String>,
    boundary_type: String,
    components: Option<String>,
    color: Option<String>,
    position_x: Option<f64>,
    position_y: Option<f64>,
    width: Option<f64>,
    height: Option<f64>,
}

impl TryFrom<TrustBoundaryRow> for TrustBoundary {
    type Error = anyhow::Error;

    fn try_from(row: TrustBoundaryRow) -> Result<Self> {
        let component_strs: Vec<String> = row.components
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();
        let components: Vec<Uuid> = component_strs
            .iter()
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();

        Ok(TrustBoundary {
            id: Uuid::parse_str(&row.id)?,
            threat_model_id: Uuid::parse_str(&row.threat_model_id)?,
            name: row.name,
            description: row.description,
            boundary_type: BoundaryType::from_str(&row.boundary_type),
            components,
            color: row.color,
            position_x: row.position_x,
            position_y: row.position_y,
            width: row.width,
            height: row.height,
        })
    }
}

#[derive(sqlx::FromRow)]
struct ThreatRow {
    id: String,
    threat_model_id: String,
    category: String,
    affected_component_id: String,
    affected_dataflow_id: Option<String>,
    title: String,
    description: String,
    attack_scenario: String,
    prerequisites: Option<String>,
    likelihood: String,
    impact: String,
    risk_rating: String,
    mitigations: Option<String>,
    status: String,
    priority: i32,
    cwe_ids: Option<String>,
    capec_ids: Option<String>,
    notes: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<ThreatRow> for StrideTheat {
    type Error = anyhow::Error;

    fn try_from(row: ThreatRow) -> Result<Self> {
        let prerequisites: Vec<String> = row.prerequisites
            .as_ref()
            .and_then(|p| serde_json::from_str(p).ok())
            .unwrap_or_default();
        let mitigation_strs: Vec<String> = row.mitigations
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();
        let mitigations: Vec<Uuid> = mitigation_strs
            .iter()
            .filter_map(|s| Uuid::parse_str(s).ok())
            .collect();
        let cwe_ids: Vec<String> = row.cwe_ids
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();
        let capec_ids: Vec<String> = row.capec_ids
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        Ok(StrideTheat {
            id: Uuid::parse_str(&row.id)?,
            threat_model_id: Uuid::parse_str(&row.threat_model_id)?,
            category: StrideCategory::from_str(&row.category),
            affected_component_id: Uuid::parse_str(&row.affected_component_id)?,
            affected_dataflow_id: row.affected_dataflow_id.as_ref().and_then(|id| Uuid::parse_str(id).ok()),
            title: row.title,
            description: row.description,
            attack_scenario: row.attack_scenario,
            prerequisites,
            likelihood: Likelihood::from_str(&row.likelihood),
            impact: Impact::from_str(&row.impact),
            risk_rating: RiskRating::from_str(&row.risk_rating),
            mitigations,
            status: ThreatStatus::from_str(&row.status),
            priority: row.priority as u32,
            cwe_ids,
            capec_ids,
            notes: row.notes,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&Utc),
        })
    }
}

#[derive(sqlx::FromRow)]
struct MitigationRow {
    id: String,
    threat_model_id: String,
    title: String,
    description: String,
    control_type: String,
    implementation_status: String,
    implementation_notes: Option<String>,
    linked_controls: Option<String>,
    effort_estimate: Option<String>,
    cost_estimate: Option<String>,
    effectiveness: Option<i32>,
    owner: Option<String>,
    due_date: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<MitigationRow> for Mitigation {
    type Error = anyhow::Error;

    fn try_from(row: MitigationRow) -> Result<Self> {
        let linked_controls: Vec<String> = row.linked_controls
            .as_ref()
            .and_then(|c| serde_json::from_str(c).ok())
            .unwrap_or_default();

        Ok(Mitigation {
            id: Uuid::parse_str(&row.id)?,
            threat_model_id: Uuid::parse_str(&row.threat_model_id)?,
            title: row.title,
            description: row.description,
            control_type: ControlType::from_str(&row.control_type),
            implementation_status: ImplementationStatus::from_str(&row.implementation_status),
            implementation_notes: row.implementation_notes,
            linked_controls,
            effort_estimate: row.effort_estimate,
            cost_estimate: row.cost_estimate,
            effectiveness: row.effectiveness.map(|e| e as u32),
            owner: row.owner,
            due_date: row.due_date.as_ref().and_then(|d| DateTime::parse_from_rfc3339(d).ok()).map(|d| d.with_timezone(&Utc)),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&Utc),
        })
    }
}
