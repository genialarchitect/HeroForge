//! Database operations for agent mesh networking
//!
//! This module provides CRUD operations for:
//! - Agent mesh configuration
//! - Agent clusters
//! - Peer connection history

use anyhow::Result;
use chrono::Utc;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::agents::mesh::types::{AgentCluster, AgentMeshConfig, AgentPeerConnection};

// ============================================================================
// Agent Mesh Config Operations
// ============================================================================

/// Create mesh configuration for an agent
pub async fn create_mesh_config(
    pool: &SqlitePool,
    agent_id: &str,
    enabled: bool,
    mesh_port: i32,
    external_address: Option<&str>,
    cluster_id: Option<&str>,
    cluster_role: Option<&str>,
    config_json: Option<&str>,
) -> Result<AgentMeshConfig> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO agent_mesh_config (
            id, agent_id, enabled, mesh_port, external_address,
            cluster_id, cluster_role, config_json, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
        "#,
    )
    .bind(&id)
    .bind(agent_id)
    .bind(enabled)
    .bind(mesh_port)
    .bind(external_address)
    .bind(cluster_id)
    .bind(cluster_role)
    .bind(config_json)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentMeshConfig {
        id,
        agent_id: agent_id.to_string(),
        enabled,
        mesh_port,
        external_address: external_address.map(String::from),
        cluster_id: cluster_id.map(String::from),
        cluster_role: cluster_role.map(String::from),
        config_json: config_json.map(String::from),
        created_at: now,
        updated_at: now,
    })
}

/// Get mesh configuration for an agent
pub async fn get_mesh_config(pool: &SqlitePool, agent_id: &str) -> Result<Option<AgentMeshConfig>> {
    let config = sqlx::query_as::<_, AgentMeshConfig>(
        "SELECT * FROM agent_mesh_config WHERE agent_id = ?1",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await?;

    Ok(config)
}

/// Update mesh configuration for an agent
pub async fn update_mesh_config(
    pool: &SqlitePool,
    agent_id: &str,
    enabled: Option<bool>,
    mesh_port: Option<i32>,
    external_address: Option<&str>,
    cluster_id: Option<&str>,
    cluster_role: Option<&str>,
    config_json: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    if let Some(enabled) = enabled {
        sqlx::query("UPDATE agent_mesh_config SET enabled = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(enabled)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(mesh_port) = mesh_port {
        sqlx::query("UPDATE agent_mesh_config SET mesh_port = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(mesh_port)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(external_address) = external_address {
        sqlx::query("UPDATE agent_mesh_config SET external_address = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(external_address)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(cluster_id) = cluster_id {
        sqlx::query("UPDATE agent_mesh_config SET cluster_id = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(cluster_id)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(cluster_role) = cluster_role {
        sqlx::query("UPDATE agent_mesh_config SET cluster_role = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(cluster_role)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    if let Some(config_json) = config_json {
        sqlx::query("UPDATE agent_mesh_config SET config_json = ?1, updated_at = ?2 WHERE agent_id = ?3")
            .bind(config_json)
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Delete mesh configuration for an agent
pub async fn delete_mesh_config(pool: &SqlitePool, agent_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM agent_mesh_config WHERE agent_id = ?1")
        .bind(agent_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get all mesh-enabled agents
pub async fn get_mesh_enabled_agents(pool: &SqlitePool) -> Result<Vec<AgentMeshConfig>> {
    let configs = sqlx::query_as::<_, AgentMeshConfig>(
        "SELECT * FROM agent_mesh_config WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await?;

    Ok(configs)
}

/// Get agents in a cluster
pub async fn get_cluster_agents(pool: &SqlitePool, cluster_id: &str) -> Result<Vec<AgentMeshConfig>> {
    let configs = sqlx::query_as::<_, AgentMeshConfig>(
        "SELECT * FROM agent_mesh_config WHERE cluster_id = ?1",
    )
    .bind(cluster_id)
    .fetch_all(pool)
    .await?;

    Ok(configs)
}

// ============================================================================
// Agent Cluster Operations
// ============================================================================

/// Create a new agent cluster
pub async fn create_cluster(
    pool: &SqlitePool,
    user_id: &str,
    name: &str,
    description: Option<&str>,
    leader_agent_id: Option<&str>,
    config_json: Option<&str>,
) -> Result<AgentCluster> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO agent_clusters (
            id, user_id, name, description, leader_agent_id,
            config_json, health_json, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(name)
    .bind(description)
    .bind(leader_agent_id)
    .bind(config_json)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentCluster {
        id,
        user_id: user_id.to_string(),
        name: name.to_string(),
        description: description.map(String::from),
        leader_agent_id: leader_agent_id.map(String::from),
        config_json: config_json.map(String::from),
        health_json: None,
        created_at: now,
        updated_at: now,
    })
}

/// Get a cluster by ID
pub async fn get_cluster_by_id(pool: &SqlitePool, cluster_id: &str) -> Result<Option<AgentCluster>> {
    let cluster = sqlx::query_as::<_, AgentCluster>(
        "SELECT * FROM agent_clusters WHERE id = ?1",
    )
    .bind(cluster_id)
    .fetch_optional(pool)
    .await?;

    Ok(cluster)
}

/// Get all clusters for a user
pub async fn get_user_clusters(pool: &SqlitePool, user_id: &str) -> Result<Vec<AgentCluster>> {
    let clusters = sqlx::query_as::<_, AgentCluster>(
        "SELECT * FROM agent_clusters WHERE user_id = ?1 ORDER BY name ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(clusters)
}

/// Update a cluster
pub async fn update_cluster(
    pool: &SqlitePool,
    cluster_id: &str,
    name: Option<&str>,
    description: Option<&str>,
    leader_agent_id: Option<&str>,
    config_json: Option<&str>,
    health_json: Option<&str>,
) -> Result<()> {
    let now = Utc::now();

    if let Some(name) = name {
        sqlx::query("UPDATE agent_clusters SET name = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(name)
            .bind(now)
            .bind(cluster_id)
            .execute(pool)
            .await?;
    }

    if let Some(description) = description {
        sqlx::query("UPDATE agent_clusters SET description = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(description)
            .bind(now)
            .bind(cluster_id)
            .execute(pool)
            .await?;
    }

    if let Some(leader_agent_id) = leader_agent_id {
        sqlx::query("UPDATE agent_clusters SET leader_agent_id = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(leader_agent_id)
            .bind(now)
            .bind(cluster_id)
            .execute(pool)
            .await?;
    }

    if let Some(config_json) = config_json {
        sqlx::query("UPDATE agent_clusters SET config_json = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(config_json)
            .bind(now)
            .bind(cluster_id)
            .execute(pool)
            .await?;
    }

    if let Some(health_json) = health_json {
        sqlx::query("UPDATE agent_clusters SET health_json = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(health_json)
            .bind(now)
            .bind(cluster_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Delete a cluster
pub async fn delete_cluster(pool: &SqlitePool, cluster_id: &str) -> Result<()> {
    // Clear cluster_id from agent mesh configs
    sqlx::query("UPDATE agent_mesh_config SET cluster_id = NULL, cluster_role = NULL WHERE cluster_id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await?;

    // Delete the cluster
    sqlx::query("DELETE FROM agent_clusters WHERE id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Set cluster leader
pub async fn set_cluster_leader(pool: &SqlitePool, cluster_id: &str, leader_agent_id: &str) -> Result<()> {
    let now = Utc::now();

    // Clear previous leader
    sqlx::query("UPDATE agent_mesh_config SET cluster_role = 'member' WHERE cluster_id = ?1 AND cluster_role = 'leader'")
        .bind(cluster_id)
        .execute(pool)
        .await?;

    // Set new leader in mesh config
    sqlx::query("UPDATE agent_mesh_config SET cluster_role = 'leader', updated_at = ?1 WHERE agent_id = ?2")
        .bind(now)
        .bind(leader_agent_id)
        .execute(pool)
        .await?;

    // Update cluster
    sqlx::query("UPDATE agent_clusters SET leader_agent_id = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(leader_agent_id)
        .bind(now)
        .bind(cluster_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Add agent to cluster
pub async fn add_agent_to_cluster(pool: &SqlitePool, agent_id: &str, cluster_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE agent_mesh_config SET cluster_id = ?1, cluster_role = 'member', updated_at = ?2 WHERE agent_id = ?3")
        .bind(cluster_id)
        .bind(now)
        .bind(agent_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Remove agent from cluster
pub async fn remove_agent_from_cluster(pool: &SqlitePool, agent_id: &str) -> Result<()> {
    let now = Utc::now();

    sqlx::query("UPDATE agent_mesh_config SET cluster_id = NULL, cluster_role = NULL, updated_at = ?1 WHERE agent_id = ?2")
        .bind(now)
        .bind(agent_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Get cluster member count
pub async fn get_cluster_member_count(pool: &SqlitePool, cluster_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM agent_mesh_config WHERE cluster_id = ?1",
    )
    .bind(cluster_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

// ============================================================================
// Peer Connection History Operations
// ============================================================================

/// Create or update peer connection record
pub async fn upsert_peer_connection(
    pool: &SqlitePool,
    agent_id: &str,
    peer_agent_id: &str,
    peer_address: &str,
    peer_port: i32,
    status: &str,
    latency_ms: Option<i32>,
) -> Result<AgentPeerConnection> {
    let now = Utc::now();

    // Check if connection exists
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM agent_peer_connections WHERE agent_id = ?1 AND peer_agent_id = ?2",
    )
    .bind(agent_id)
    .bind(peer_agent_id)
    .fetch_optional(pool)
    .await?;

    if let Some((id,)) = existing {
        // Update existing
        sqlx::query(
            r#"
            UPDATE agent_peer_connections
            SET peer_address = ?1, peer_port = ?2, status = ?3, latency_ms = ?4,
                last_attempt_at = ?5, updated_at = ?5
            WHERE id = ?6
            "#,
        )
        .bind(peer_address)
        .bind(peer_port)
        .bind(status)
        .bind(latency_ms)
        .bind(now)
        .bind(&id)
        .execute(pool)
        .await?;

        return get_peer_connection_by_id(pool, &id).await.map(|c| c.unwrap());
    }

    // Create new
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"
        INSERT INTO agent_peer_connections (
            id, agent_id, peer_agent_id, peer_address, peer_port, status,
            latency_ms, successful_pings, failed_pings,
            last_connected_at, last_attempt_at, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, NULL, ?8, ?8, ?8)
        "#,
    )
    .bind(&id)
    .bind(agent_id)
    .bind(peer_agent_id)
    .bind(peer_address)
    .bind(peer_port)
    .bind(status)
    .bind(latency_ms)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(AgentPeerConnection {
        id,
        agent_id: agent_id.to_string(),
        peer_agent_id: peer_agent_id.to_string(),
        peer_address: peer_address.to_string(),
        peer_port,
        status: status.to_string(),
        latency_ms,
        successful_pings: 0,
        failed_pings: 0,
        last_connected_at: None,
        last_attempt_at: Some(now),
        created_at: now,
        updated_at: now,
    })
}

/// Get peer connection by ID
pub async fn get_peer_connection_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<AgentPeerConnection>> {
    let connection = sqlx::query_as::<_, AgentPeerConnection>(
        "SELECT * FROM agent_peer_connections WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(connection)
}

/// Get all peer connections for an agent
pub async fn get_agent_peer_connections(
    pool: &SqlitePool,
    agent_id: &str,
) -> Result<Vec<AgentPeerConnection>> {
    let connections = sqlx::query_as::<_, AgentPeerConnection>(
        "SELECT * FROM agent_peer_connections WHERE agent_id = ?1 ORDER BY last_attempt_at DESC",
    )
    .bind(agent_id)
    .fetch_all(pool)
    .await?;

    Ok(connections)
}

/// Record successful ping
pub async fn record_successful_ping(
    pool: &SqlitePool,
    agent_id: &str,
    peer_agent_id: &str,
    latency_ms: i32,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE agent_peer_connections
        SET successful_pings = successful_pings + 1,
            latency_ms = ?1,
            status = 'online',
            last_connected_at = ?2,
            updated_at = ?2
        WHERE agent_id = ?3 AND peer_agent_id = ?4
        "#,
    )
    .bind(latency_ms)
    .bind(now)
    .bind(agent_id)
    .bind(peer_agent_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Record failed ping
pub async fn record_failed_ping(
    pool: &SqlitePool,
    agent_id: &str,
    peer_agent_id: &str,
) -> Result<()> {
    let now = Utc::now();

    sqlx::query(
        r#"
        UPDATE agent_peer_connections
        SET failed_pings = failed_pings + 1,
            status = 'disconnected',
            updated_at = ?1
        WHERE agent_id = ?2 AND peer_agent_id = ?3
        "#,
    )
    .bind(now)
    .bind(agent_id)
    .bind(peer_agent_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete peer connection
pub async fn delete_peer_connection(
    pool: &SqlitePool,
    agent_id: &str,
    peer_agent_id: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM agent_peer_connections WHERE agent_id = ?1 AND peer_agent_id = ?2")
        .bind(agent_id)
        .bind(peer_agent_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Cleanup old peer connections (inactive for more than 7 days)
pub async fn cleanup_old_peer_connections(pool: &SqlitePool, days: i64) -> Result<u64> {
    let cutoff = Utc::now() - chrono::Duration::days(days);

    let result = sqlx::query(
        r#"
        DELETE FROM agent_peer_connections
        WHERE last_attempt_at < ?1
        AND status = 'disconnected'
        "#,
    )
    .bind(cutoff)
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Get peer connection statistics for an agent
pub async fn get_peer_connection_stats(
    pool: &SqlitePool,
    agent_id: &str,
) -> Result<PeerConnectionStats> {
    let row: (i64, i64, i64, Option<f64>) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) as total_peers,
            SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_peers,
            SUM(CASE WHEN status = 'disconnected' THEN 1 ELSE 0 END) as disconnected_peers,
            AVG(latency_ms) as avg_latency
        FROM agent_peer_connections
        WHERE agent_id = ?1
        "#,
    )
    .bind(agent_id)
    .fetch_one(pool)
    .await?;

    Ok(PeerConnectionStats {
        total_peers: row.0,
        online_peers: row.1,
        disconnected_peers: row.2,
        average_latency_ms: row.3,
    })
}

/// Peer connection statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerConnectionStats {
    pub total_peers: i64,
    pub online_peers: i64,
    pub disconnected_peers: i64,
    pub average_latency_ms: Option<f64>,
}
