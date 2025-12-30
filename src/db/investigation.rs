use anyhow::Result;
use sqlx::SqlitePool;
use crate::investigation::types::*;
use uuid::Uuid;
use chrono::Utc;

pub async fn run_migrations(pool: &SqlitePool) -> Result<()> {
    // Investigations table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            investigation_type TEXT NOT NULL,
            status TEXT NOT NULL,
            priority TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Timeline events table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigation_timeline_events (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            entities TEXT,
            raw_data TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Graph entities table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigation_graph_entities (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            properties TEXT,
            risk_score REAL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Graph relationships table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigation_graph_relationships (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            source_entity_id TEXT NOT NULL,
            target_entity_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            properties TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
            FOREIGN KEY (source_entity_id) REFERENCES investigation_graph_entities(id) ON DELETE CASCADE,
            FOREIGN KEY (target_entity_id) REFERENCES investigation_graph_entities(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Memory artifacts table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigation_memory_artifacts (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            name TEXT NOT NULL,
            pid INTEGER,
            data TEXT,
            suspicious BOOLEAN NOT NULL DEFAULT 0,
            indicators TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // PCAP sessions table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS investigation_pcap_sessions (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            start_time TEXT NOT NULL,
            end_time TEXT,
            packets INTEGER NOT NULL,
            bytes INTEGER NOT NULL,
            suspicious BOOLEAN NOT NULL DEFAULT 0,
            indicators TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create indexes
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_investigations_user_id ON investigations(user_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_timeline_investigation_id ON investigation_timeline_events(investigation_id)")
        .execute(pool)
        .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_graph_entities_investigation_id ON investigation_graph_entities(investigation_id)")
        .execute(pool)
        .await?;

    Ok(())
}

// CRUD operations for investigations
pub async fn create_investigation(
    pool: &SqlitePool,
    user_id: &str,
    req: CreateInvestigationRequest,
) -> Result<Investigation> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO investigations (id, user_id, name, description, investigation_type, status, priority, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.investigation_type)
    .bind("Active")
    .bind(&req.priority)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    get_investigation_by_id(pool, &id).await
}

pub async fn get_investigation_by_id(pool: &SqlitePool, id: &str) -> Result<Investigation> {
    let investigation = sqlx::query_as::<_, Investigation>(
        "SELECT * FROM investigations WHERE id = ?"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(investigation)
}

pub async fn list_user_investigations(pool: &SqlitePool, user_id: &str) -> Result<Vec<Investigation>> {
    let investigations = sqlx::query_as::<_, Investigation>(
        "SELECT * FROM investigations WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(investigations)
}

// Timeline event operations
pub async fn add_timeline_event(
    pool: &SqlitePool,
    investigation_id: &str,
    req: AddTimelineEventRequest,
) -> Result<TimelineEvent> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let entities_json = req.entities.map(|e| serde_json::to_string(&e).ok()).flatten();
    let raw_data_json = req.raw_data.map(|d| d.to_string());
    let tags_json = req.tags.map(|t| serde_json::to_string(&t).ok()).flatten();

    sqlx::query(
        r#"
        INSERT INTO investigation_timeline_events
        (id, investigation_id, timestamp, event_type, source, description, severity, entities, raw_data, tags, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(investigation_id)
    .bind(req.timestamp.to_rfc3339())
    .bind(&req.event_type)
    .bind(&req.source)
    .bind(&req.description)
    .bind(&req.severity)
    .bind(&entities_json)
    .bind(&raw_data_json)
    .bind(&tags_json)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    let event = sqlx::query_as::<_, TimelineEvent>(
        "SELECT * FROM investigation_timeline_events WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(event)
}

pub async fn get_timeline_events(pool: &SqlitePool, investigation_id: &str) -> Result<Vec<TimelineEvent>> {
    let events = sqlx::query_as::<_, TimelineEvent>(
        "SELECT * FROM investigation_timeline_events WHERE investigation_id = ? ORDER BY timestamp ASC"
    )
    .bind(investigation_id)
    .fetch_all(pool)
    .await?;

    Ok(events)
}

// Graph entity operations
pub async fn add_graph_entity(
    pool: &SqlitePool,
    investigation_id: &str,
    req: AddGraphEntityRequest,
) -> Result<GraphEntity> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let properties_json = req.properties.map(|p| p.to_string());

    sqlx::query(
        r#"
        INSERT INTO investigation_graph_entities
        (id, investigation_id, entity_type, entity_value, properties, risk_score, first_seen, last_seen, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(investigation_id)
    .bind(&req.entity_type)
    .bind(&req.entity_value)
    .bind(&properties_json)
    .bind(req.risk_score)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    let entity = sqlx::query_as::<_, GraphEntity>(
        "SELECT * FROM investigation_graph_entities WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(entity)
}

pub async fn get_graph_entities(pool: &SqlitePool, investigation_id: &str) -> Result<Vec<GraphEntity>> {
    let entities = sqlx::query_as::<_, GraphEntity>(
        "SELECT * FROM investigation_graph_entities WHERE investigation_id = ?"
    )
    .bind(investigation_id)
    .fetch_all(pool)
    .await?;

    Ok(entities)
}

// Graph relationship operations
pub async fn add_graph_relationship(
    pool: &SqlitePool,
    investigation_id: &str,
    req: AddGraphRelationshipRequest,
) -> Result<GraphRelationship> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let properties_json = req.properties.map(|p| p.to_string());

    sqlx::query(
        r#"
        INSERT INTO investigation_graph_relationships
        (id, investigation_id, source_entity_id, target_entity_id, relationship_type, properties, first_seen, last_seen, count, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&id)
    .bind(investigation_id)
    .bind(&req.source_entity_id)
    .bind(&req.target_entity_id)
    .bind(&req.relationship_type)
    .bind(&properties_json)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind(1)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    let relationship = sqlx::query_as::<_, GraphRelationship>(
        "SELECT * FROM investigation_graph_relationships WHERE id = ?"
    )
    .bind(&id)
    .fetch_one(pool)
    .await?;

    Ok(relationship)
}

pub async fn get_graph_relationships(pool: &SqlitePool, investigation_id: &str) -> Result<Vec<GraphRelationship>> {
    let relationships = sqlx::query_as::<_, GraphRelationship>(
        "SELECT * FROM investigation_graph_relationships WHERE investigation_id = ?"
    )
    .bind(investigation_id)
    .fetch_all(pool)
    .await?;

    Ok(relationships)
}
