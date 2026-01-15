//! Database operations for Attack Path Analysis
//!
//! Provides CRUD operations for attack paths, nodes, and edges.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use utoipa::ToSchema;

use crate::scanner::attack_paths::{AttackPath, RiskLevel};
use crate::scanner::attack_paths::graph::{AttackNode, AttackEdge, NodeType};

/// Database model for attack paths
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackPathRecord {
    pub id: String,
    pub scan_id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub risk_level: String,
    pub probability: Option<f64>,
    pub total_cvss: Option<f64>,
    pub path_length: Option<i32>,
    pub description: Option<String>,
    pub mitigation_steps: Option<String>, // JSON array
    pub created_at: DateTime<Utc>,
}

/// Database model for attack nodes
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackNodeRecord {
    pub id: String,
    pub path_id: String,
    pub host_ip: Option<String>,
    pub port: Option<i32>,
    pub service: Option<String>,
    pub vulnerability_ids: Option<String>, // JSON array
    pub node_type: String,
    pub position_x: Option<f64>,
    pub position_y: Option<f64>,
    pub metadata: Option<String>, // JSON object
}

/// Database model for attack edges
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttackEdgeRecord {
    pub id: String,
    pub path_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub attack_technique: Option<String>,
    pub technique_id: Option<String>,
    pub likelihood: Option<f64>,
    pub impact: Option<f64>,
    pub description: Option<String>,
}

/// Store an attack path in the database
pub async fn create_attack_path(
    pool: &SqlitePool,
    scan_id: &str,
    user_id: &str,
    path: &AttackPath,
) -> Result<AttackPathRecord> {
    let now = Utc::now();
    let mitigation_json = serde_json::to_string(&path.mitigation_steps)?;

    sqlx::query(
        r#"
        INSERT INTO attack_paths (
            id, scan_id, user_id, name, risk_level, probability, total_cvss,
            path_length, description, mitigation_steps, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&path.id)
    .bind(scan_id)
    .bind(user_id)
    .bind(&path.name)
    .bind(path.risk_level.as_str())
    .bind(path.probability)
    .bind(path.total_cvss)
    .bind(path.path_length as i32)
    .bind(&path.description)
    .bind(&mitigation_json)
    .bind(&now)
    .execute(pool)
    .await?;

    // Store nodes
    for node in &path.nodes {
        create_attack_node(pool, &path.id, node).await?;
    }

    // Store edges
    for edge in &path.edges {
        create_attack_edge(pool, &path.id, edge).await?;
    }

    Ok(AttackPathRecord {
        id: path.id.clone(),
        scan_id: scan_id.to_string(),
        user_id: user_id.to_string(),
        name: path.name.clone(),
        risk_level: path.risk_level.as_str().to_string(),
        probability: Some(path.probability),
        total_cvss: Some(path.total_cvss),
        path_length: Some(path.path_length as i32),
        description: path.description.clone(),
        mitigation_steps: Some(mitigation_json),
        created_at: now,
    })
}

/// Store an attack node in the database
async fn create_attack_node(
    pool: &SqlitePool,
    path_id: &str,
    node: &AttackNode,
) -> Result<()> {
    let vuln_ids_json = serde_json::to_string(&node.vulnerability_ids)?;
    let metadata_json = serde_json::to_string(&node.metadata)?;

    sqlx::query(
        r#"
        INSERT INTO attack_nodes (
            id, path_id, host_ip, port, service, vulnerability_ids,
            node_type, position_x, position_y, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&node.id)
    .bind(path_id)
    .bind(&node.host_ip)
    .bind(node.port.map(|p| p as i32))
    .bind(&node.service)
    .bind(&vuln_ids_json)
    .bind(node.node_type.as_str())
    .bind(node.position_x)
    .bind(node.position_y)
    .bind(&metadata_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Store an attack edge in the database
async fn create_attack_edge(
    pool: &SqlitePool,
    path_id: &str,
    edge: &AttackEdge,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO attack_edges (
            id, path_id, source_node_id, target_node_id, attack_technique,
            technique_id, likelihood, impact, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&edge.id)
    .bind(path_id)
    .bind(&edge.source_node_id)
    .bind(&edge.target_node_id)
    .bind(&edge.attack_technique)
    .bind(&edge.technique_id)
    .bind(edge.likelihood)
    .bind(edge.impact)
    .bind(&edge.description)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all attack paths for a scan
pub async fn get_attack_paths_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<AttackPathRecord>> {
    let paths = sqlx::query_as::<_, AttackPathRecord>(
        r#"
        SELECT id, scan_id, user_id, name, risk_level, probability, total_cvss,
               path_length, description, mitigation_steps, created_at
        FROM attack_paths
        WHERE scan_id = ?
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            probability DESC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(paths)
}

/// Get all attack paths for a user (across all scans)
pub async fn get_attack_paths_by_user(
    pool: &SqlitePool,
    user_id: &str,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Vec<AttackPathRecord>> {
    let limit = limit.unwrap_or(50);
    let offset = offset.unwrap_or(0);

    let paths = sqlx::query_as::<_, AttackPathRecord>(
        r#"
        SELECT id, scan_id, user_id, name, risk_level, probability, total_cvss,
               path_length, description, mitigation_steps, created_at
        FROM attack_paths
        WHERE user_id = ?
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            created_at DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(paths)
}

/// Count total attack paths for a user
pub async fn count_attack_paths_by_user(pool: &SqlitePool, user_id: &str) -> Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM attack_paths WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

/// Get critical attack paths for a scan (high and critical risk)
pub async fn get_critical_attack_paths(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<Vec<AttackPathRecord>> {
    let paths = sqlx::query_as::<_, AttackPathRecord>(
        r#"
        SELECT id, scan_id, user_id, name, risk_level, probability, total_cvss,
               path_length, description, mitigation_steps, created_at
        FROM attack_paths
        WHERE scan_id = ? AND risk_level IN ('critical', 'high')
        ORDER BY
            CASE risk_level
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
            END,
            probability DESC
        "#,
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;

    Ok(paths)
}

/// Get a single attack path by ID
pub async fn get_attack_path_by_id(
    pool: &SqlitePool,
    path_id: &str,
) -> Result<Option<AttackPathRecord>> {
    let path = sqlx::query_as::<_, AttackPathRecord>(
        r#"
        SELECT id, scan_id, user_id, name, risk_level, probability, total_cvss,
               path_length, description, mitigation_steps, created_at
        FROM attack_paths
        WHERE id = ?
        "#,
    )
    .bind(path_id)
    .fetch_optional(pool)
    .await?;

    Ok(path)
}

/// Get nodes for an attack path
pub async fn get_attack_nodes(
    pool: &SqlitePool,
    path_id: &str,
) -> Result<Vec<AttackNodeRecord>> {
    let nodes = sqlx::query_as::<_, AttackNodeRecord>(
        r#"
        SELECT id, path_id, host_ip, port, service, vulnerability_ids,
               node_type, position_x, position_y, metadata
        FROM attack_nodes
        WHERE path_id = ?
        "#,
    )
    .bind(path_id)
    .fetch_all(pool)
    .await?;

    Ok(nodes)
}

/// Get edges for an attack path
pub async fn get_attack_edges(
    pool: &SqlitePool,
    path_id: &str,
) -> Result<Vec<AttackEdgeRecord>> {
    let edges = sqlx::query_as::<_, AttackEdgeRecord>(
        r#"
        SELECT id, path_id, source_node_id, target_node_id, attack_technique,
               technique_id, likelihood, impact, description
        FROM attack_edges
        WHERE path_id = ?
        "#,
    )
    .bind(path_id)
    .fetch_all(pool)
    .await?;

    Ok(edges)
}

/// Get a complete attack path with nodes and edges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathWithDetails {
    pub path: AttackPathRecord,
    pub nodes: Vec<AttackNodeRecord>,
    pub edges: Vec<AttackEdgeRecord>,
}

pub async fn get_attack_path_with_details(
    pool: &SqlitePool,
    path_id: &str,
) -> Result<Option<AttackPathWithDetails>> {
    let path = get_attack_path_by_id(pool, path_id).await?;

    match path {
        Some(p) => {
            let nodes = get_attack_nodes(pool, path_id).await?;
            let edges = get_attack_edges(pool, path_id).await?;

            Ok(Some(AttackPathWithDetails {
                path: p,
                nodes,
                edges,
            }))
        }
        None => Ok(None),
    }
}

/// Delete all attack paths for a scan
pub async fn delete_attack_paths_by_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<u64> {
    // Due to foreign key constraints, deleting paths will cascade to nodes and edges
    let result = sqlx::query("DELETE FROM attack_paths WHERE scan_id = ?")
        .bind(scan_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Delete a single attack path
pub async fn delete_attack_path(
    pool: &SqlitePool,
    path_id: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM attack_paths WHERE id = ?")
        .bind(path_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Get attack path statistics for a scan
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AttackPathStats {
    pub total_paths: i64,
    pub critical_paths: i64,
    pub high_paths: i64,
    pub medium_paths: i64,
    pub low_paths: i64,
    pub avg_path_length: Option<f64>,
    pub avg_probability: Option<f64>,
    pub total_nodes: i64,
    pub total_edges: i64,
}

pub async fn get_attack_path_stats(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<AttackPathStats> {
    // Get path counts by risk level
    let path_counts = sqlx::query_as::<_, (i64, i64, i64, i64, i64, Option<f64>, Option<f64>)>(
        r#"
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) as low,
            AVG(path_length) as avg_length,
            AVG(probability) as avg_probability
        FROM attack_paths
        WHERE scan_id = ?
        "#,
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    // Get node and edge counts
    let node_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM attack_nodes
        WHERE path_id IN (SELECT id FROM attack_paths WHERE scan_id = ?)
        "#,
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    let edge_count: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM attack_edges
        WHERE path_id IN (SELECT id FROM attack_paths WHERE scan_id = ?)
        "#,
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    Ok(AttackPathStats {
        total_paths: path_counts.0,
        critical_paths: path_counts.1,
        high_paths: path_counts.2,
        medium_paths: path_counts.3,
        low_paths: path_counts.4,
        avg_path_length: path_counts.5,
        avg_probability: path_counts.6,
        total_nodes: node_count.0,
        total_edges: edge_count.0,
    })
}

/// Check if attack paths exist for a scan
pub async fn attack_paths_exist(
    pool: &SqlitePool,
    scan_id: &str,
) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM attack_paths WHERE scan_id = ?",
    )
    .bind(scan_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0 > 0)
}

/// Convert database records back to domain models
impl AttackNodeRecord {
    pub fn to_domain(&self) -> AttackNode {
        let vulnerability_ids: Vec<String> = self
            .vulnerability_ids
            .as_ref()
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_default();

        let metadata: std::collections::HashMap<String, serde_json::Value> = self
            .metadata
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        let node_type = NodeType::from_str(&self.node_type).unwrap_or(NodeType::Pivot);

        AttackNode {
            id: self.id.clone(),
            host_ip: self.host_ip.clone(),
            port: self.port.map(|p| p as u16),
            service: self.service.clone(),
            vulnerability_ids,
            node_type,
            position_x: self.position_x.unwrap_or(0.0),
            position_y: self.position_y.unwrap_or(0.0),
            metadata,
        }
    }
}

impl AttackEdgeRecord {
    pub fn to_domain(&self) -> AttackEdge {
        AttackEdge {
            id: self.id.clone(),
            source_node_id: self.source_node_id.clone(),
            target_node_id: self.target_node_id.clone(),
            attack_technique: self.attack_technique.clone(),
            technique_id: self.technique_id.clone(),
            likelihood: self.likelihood.unwrap_or(0.5),
            impact: self.impact.unwrap_or(5.0),
            description: self.description.clone(),
        }
    }
}

impl AttackPathRecord {
    pub fn to_domain(&self, nodes: Vec<AttackNode>, edges: Vec<AttackEdge>) -> AttackPath {
        let mitigation_steps: Vec<String> = self
            .mitigation_steps
            .as_ref()
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default();

        let risk_level = RiskLevel::from_str(&self.risk_level).unwrap_or(RiskLevel::Low);

        AttackPath {
            id: self.id.clone(),
            name: self.name.clone(),
            risk_level,
            probability: self.probability.unwrap_or(0.0),
            total_cvss: self.total_cvss.unwrap_or(0.0),
            path_length: self.path_length.unwrap_or(0) as usize,
            description: self.description.clone(),
            mitigation_steps,
            nodes,
            edges,
        }
    }
}
