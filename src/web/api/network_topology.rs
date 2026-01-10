//! Network Topology API for cATO Network Map
//!
//! Provides endpoints for managing and retrieving network topology data
//! from discovered assets, manual configurations, and scan results.

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String, // "networkDevice"
    pub position: Position,
    pub data: NodeData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeData {
    pub label: String,
    pub device_type: String,
    pub security_zone: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub compliance_status: String,
    pub controls_assessed: Option<i32>,
    pub controls_passing: Option<i32>,
    pub vulnerabilities: Option<i32>,
    pub description: Option<String>,
    pub ports: Option<Vec<PortInfo>>,
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortInfo {
    pub port: i32,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: Option<String>,
    pub animated: Option<bool>,
    pub style: Option<EdgeStyle>,
    pub marker_end: Option<MarkerEnd>,
    pub data: Option<EdgeData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStyle {
    pub stroke: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stroke_width: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stroke_dasharray: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MarkerEnd {
    #[serde(rename = "type")]
    pub marker_type: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EdgeData {
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub encrypted: Option<bool>,
    pub data_classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTopology {
    pub nodes: Vec<NetworkNode>,
    pub edges: Vec<NetworkEdge>,
    pub metadata: TopologyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyMetadata {
    pub name: String,
    pub description: Option<String>,
    pub last_updated: String,
    pub total_devices: i32,
    pub total_connections: i32,
    pub data_source: String, // "discovered", "manual", "imported"
}

#[derive(Debug, Deserialize)]
pub struct GetTopologyQuery {
    pub engagement_id: Option<String>,
    pub include_discovered: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveTopologyRequest {
    pub name: String,
    pub description: Option<String>,
    pub engagement_id: Option<String>,
    pub nodes: Vec<NetworkNode>,
    pub edges: Vec<NetworkEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddNodeRequest {
    pub topology_id: String,
    pub label: String,
    pub device_type: String,
    pub security_zone: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub position: Position,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddConnectionRequest {
    pub topology_id: String,
    pub source_id: String,
    pub target_id: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub label: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get network topology - combines discovered assets with manual topology
pub async fn get_topology(
    pool: web::Data<SqlitePool>,
    query: web::Query<GetTopologyQuery>,
) -> Result<HttpResponse> {
    let include_discovered = query.include_discovered.unwrap_or(true);

    // First, try to load saved topology
    let saved_topology = if let Some(eng_id) = &query.engagement_id {
        load_saved_topology(pool.get_ref(), Some(eng_id)).await
    } else {
        load_saved_topology(pool.get_ref(), None).await
    };

    // If we have a saved topology, return it (optionally merged with discovered assets)
    if let Ok(Some(mut topology)) = saved_topology {
        if include_discovered {
            // Merge in any newly discovered assets not in the topology
            let discovered = get_discovered_assets(pool.get_ref(), query.engagement_id.as_deref()).await;
            if let Ok(discovered_nodes) = discovered {
                merge_discovered_nodes(&mut topology, discovered_nodes);
            }
        }
        return Ok(HttpResponse::Ok().json(topology));
    }

    // No saved topology - build from discovered assets
    let topology = build_topology_from_discovered(pool.get_ref(), query.engagement_id.as_deref()).await
        .map_err(|e| {
            log::error!("Failed to build topology: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to build topology")
        })?;

    Ok(HttpResponse::Ok().json(topology))
}

/// Save network topology
pub async fn save_topology(
    pool: web::Data<SqlitePool>,
    body: web::Json<SaveTopologyRequest>,
) -> Result<HttpResponse> {
    let request = body.into_inner();

    let topology_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Serialize nodes and edges to JSON
    let nodes_json = serde_json::to_string(&request.nodes)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid nodes data"))?;
    let edges_json = serde_json::to_string(&request.edges)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid edges data"))?;

    // Save to database
    sqlx::query(
        r#"
        INSERT INTO network_topologies (id, name, description, engagement_id, nodes, edges, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id) DO UPDATE SET
            name = excluded.name,
            description = excluded.description,
            nodes = excluded.nodes,
            edges = excluded.edges,
            updated_at = excluded.updated_at
        "#
    )
    .bind(&topology_id)
    .bind(&request.name)
    .bind(&request.description)
    .bind(&request.engagement_id)
    .bind(&nodes_json)
    .bind(&edges_json)
    .bind(&now)
    .bind(&now)
    .execute(pool.get_ref())
    .await
    .map_err(|e| {
        log::error!("Failed to save topology: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to save topology")
    })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "topologyId": topology_id,
        "message": "Topology saved successfully"
    })))
}

/// Get list of saved topologies
pub async fn list_topologies(
    pool: web::Data<SqlitePool>,
) -> Result<HttpResponse> {
    let topologies: Vec<(String, String, Option<String>, Option<String>, String, String)> = sqlx::query_as(
        r#"
        SELECT id, name, description, engagement_id, created_at, updated_at
        FROM network_topologies
        ORDER BY updated_at DESC
        "#
    )
    .fetch_all(pool.get_ref())
    .await
    .unwrap_or_default();

    let result: Vec<serde_json::Value> = topologies.into_iter().map(|(id, name, desc, eng_id, created, updated)| {
        serde_json::json!({
            "id": id,
            "name": name,
            "description": desc,
            "engagementId": eng_id,
            "createdAt": created,
            "updatedAt": updated
        })
    }).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "topologies": result
    })))
}

/// Delete a saved topology
pub async fn delete_topology(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let topology_id = path.into_inner();

    sqlx::query("DELETE FROM network_topologies WHERE id = ?")
        .bind(&topology_id)
        .execute(pool.get_ref())
        .await
        .map_err(|e| {
            log::error!("Failed to delete topology: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to delete topology")
        })?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Topology deleted"
    })))
}

/// Import topology from scan results
pub async fn import_from_scan(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
) -> Result<HttpResponse> {
    let scan_id = path.into_inner();

    let topology = build_topology_from_scan(pool.get_ref(), &scan_id).await
        .map_err(|e| {
            log::error!("Failed to import from scan: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to import from scan")
        })?;

    Ok(HttpResponse::Ok().json(topology))
}

// ============================================================================
// Helper Functions
// ============================================================================

async fn load_saved_topology(
    pool: &SqlitePool,
    engagement_id: Option<&str>,
) -> anyhow::Result<Option<NetworkTopology>> {
    let row: Option<(String, String, Option<String>, String, String, String, String)> = if let Some(eng_id) = engagement_id {
        sqlx::query_as(
            "SELECT id, name, description, nodes, edges, created_at, updated_at FROM network_topologies WHERE engagement_id = ?"
        )
        .bind(eng_id)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, name, description, nodes, edges, created_at, updated_at FROM network_topologies WHERE engagement_id IS NULL ORDER BY updated_at DESC LIMIT 1"
        )
        .fetch_optional(pool)
        .await?
    };

    if let Some((id, name, description, nodes_json, edges_json, _created, updated)) = row {
        let nodes: Vec<NetworkNode> = serde_json::from_str(&nodes_json).unwrap_or_default();
        let edges: Vec<NetworkEdge> = serde_json::from_str(&edges_json).unwrap_or_default();

        Ok(Some(NetworkTopology {
            nodes: nodes.clone(),
            edges: edges.clone(),
            metadata: TopologyMetadata {
                name,
                description,
                last_updated: updated,
                total_devices: nodes.len() as i32,
                total_connections: edges.len() as i32,
                data_source: "manual".to_string(),
            },
        }))
    } else {
        Ok(None)
    }
}

async fn get_discovered_assets(
    pool: &SqlitePool,
    engagement_id: Option<&str>,
) -> anyhow::Result<Vec<NetworkNode>> {
    // Get assets from asset table
    let assets: Vec<(String, String, Option<String>, Option<String>, Option<String>, String)> = sqlx::query_as(
        r#"
        SELECT id, ip_address, hostname, os_family, os_version, status
        FROM assets
        WHERE status = 'active'
        ORDER BY ip_address
        LIMIT 100
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    // Get ports for each asset
    let mut asset_ports: HashMap<String, Vec<PortInfo>> = HashMap::new();
    let ports: Vec<(String, i32, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT asset_id, port, protocol, service_name, service_version
        FROM asset_ports
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (asset_id, port, protocol, service, version) in ports {
        asset_ports.entry(asset_id).or_default().push(PortInfo {
            port,
            protocol,
            service,
            version,
        });
    }

    // Get vulnerability counts
    let vuln_counts: HashMap<String, i32> = sqlx::query_as::<_, (String, i32)>(
        r#"
        SELECT asset_id, COUNT(*) as count
        FROM vulnerabilities
        WHERE status != 'resolved'
        GROUP BY asset_id
        "#
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    // Convert to nodes
    let mut nodes = Vec::new();
    let mut y_offset = 100.0;

    for (idx, (id, ip, hostname, os_family, os_version, status)) in assets.into_iter().enumerate() {
        let device_type = infer_device_type(&os_family, &hostname, &asset_ports.get(&id));
        let security_zone = infer_security_zone(&ip);
        let os_string = match (os_family.as_ref(), os_version.as_ref()) {
            (Some(f), Some(v)) => Some(format!("{} {}", f, v)),
            (Some(f), None) => Some(f.clone()),
            _ => None,
        };

        nodes.push(NetworkNode {
            id: id.clone(),
            node_type: "networkDevice".to_string(),
            position: Position {
                x: 200.0 + (idx % 4) as f64 * 200.0,
                y: y_offset,
            },
            data: NodeData {
                label: hostname.clone().unwrap_or_else(|| ip.clone()),
                device_type,
                security_zone,
                ip_address: Some(ip),
                hostname,
                os: os_string,
                compliance_status: "not_assessed".to_string(),
                controls_assessed: None,
                controls_passing: None,
                vulnerabilities: vuln_counts.get(&id).copied(),
                description: None,
                ports: asset_ports.get(&id).cloned(),
                asset_id: Some(id),
            },
        });

        if (idx + 1) % 4 == 0 {
            y_offset += 150.0;
        }
    }

    Ok(nodes)
}

async fn build_topology_from_discovered(
    pool: &SqlitePool,
    engagement_id: Option<&str>,
) -> anyhow::Result<NetworkTopology> {
    let nodes = get_discovered_assets(pool, engagement_id).await?;

    // Build edges based on common network patterns
    let edges = infer_network_connections(&nodes);

    Ok(NetworkTopology {
        nodes: nodes.clone(),
        edges: edges.clone(),
        metadata: TopologyMetadata {
            name: "Discovered Network Topology".to_string(),
            description: Some("Auto-generated from discovered assets".to_string()),
            last_updated: chrono::Utc::now().to_rfc3339(),
            total_devices: nodes.len() as i32,
            total_connections: edges.len() as i32,
            data_source: "discovered".to_string(),
        },
    })
}

async fn build_topology_from_scan(
    pool: &SqlitePool,
    scan_id: &str,
) -> anyhow::Result<NetworkTopology> {
    // Get hosts from scan results
    let hosts: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT DISTINCT
            json_extract(host, '$.ip') as ip,
            json_extract(host, '$.hostname') as hostname,
            json_extract(host, '$.os.name') as os
        FROM scan_hosts
        WHERE scan_id = ?
        "#
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut nodes = Vec::new();
    let mut y_offset = 100.0;

    for (idx, (ip, hostname, os)) in hosts.into_iter().enumerate() {
        let ip_str = if ip.is_empty() { format!("host-{}", idx) } else { ip };
        let device_type = infer_device_type(&os, &hostname, &None);
        let security_zone = infer_security_zone(&ip_str);

        nodes.push(NetworkNode {
            id: format!("scan-{}-{}", scan_id, idx),
            node_type: "networkDevice".to_string(),
            position: Position {
                x: 200.0 + (idx % 4) as f64 * 200.0,
                y: y_offset,
            },
            data: NodeData {
                label: hostname.clone().unwrap_or_else(|| ip_str.clone()),
                device_type,
                security_zone,
                ip_address: Some(ip_str),
                hostname,
                os,
                compliance_status: "not_assessed".to_string(),
                controls_assessed: None,
                controls_passing: None,
                vulnerabilities: None,
                description: Some(format!("Imported from scan {}", scan_id)),
                ports: None,
                asset_id: None,
            },
        });

        if (idx + 1) % 4 == 0 {
            y_offset += 150.0;
        }
    }

    let edges = infer_network_connections(&nodes);

    Ok(NetworkTopology {
        nodes: nodes.clone(),
        edges: edges.clone(),
        metadata: TopologyMetadata {
            name: format!("Scan {} Topology", &scan_id[..8]),
            description: Some(format!("Imported from scan results")),
            last_updated: chrono::Utc::now().to_rfc3339(),
            total_devices: nodes.len() as i32,
            total_connections: edges.len() as i32,
            data_source: "scan".to_string(),
        },
    })
}

fn merge_discovered_nodes(topology: &mut NetworkTopology, discovered: Vec<NetworkNode>) {
    let existing_ips: std::collections::HashSet<String> = topology.nodes.iter()
        .filter_map(|n| n.data.ip_address.clone())
        .collect();

    for node in discovered {
        if let Some(ip) = &node.data.ip_address {
            if !existing_ips.contains(ip) {
                topology.nodes.push(node);
                topology.metadata.total_devices += 1;
            }
        }
    }
}

fn infer_device_type(os: &Option<String>, hostname: &Option<String>, ports: &Option<&Vec<PortInfo>>) -> String {
    let os_lower = os.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
    let host_lower = hostname.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();

    // Check hostname patterns
    if host_lower.contains("fw") || host_lower.contains("firewall") || host_lower.contains("pfsense") || host_lower.contains("fortinet") {
        return "firewall".to_string();
    }
    if host_lower.contains("router") || host_lower.contains("gw") || host_lower.contains("gateway") {
        return "router".to_string();
    }
    if host_lower.contains("switch") || host_lower.contains("sw-") {
        return "switch".to_string();
    }
    if host_lower.contains("db") || host_lower.contains("database") || host_lower.contains("sql") || host_lower.contains("postgres") || host_lower.contains("mysql") {
        return "database".to_string();
    }
    if host_lower.contains("web") || host_lower.contains("www") || host_lower.contains("nginx") || host_lower.contains("apache") {
        return "server".to_string();
    }
    if host_lower.contains("ap-") || host_lower.contains("wireless") || host_lower.contains("wifi") {
        return "wireless_ap".to_string();
    }
    if host_lower.contains("printer") || host_lower.contains("print") {
        return "printer".to_string();
    }
    if host_lower.contains("cam") || host_lower.contains("nvr") || host_lower.contains("dvr") {
        return "camera".to_string();
    }
    if host_lower.contains("vpn") {
        return "vpn".to_string();
    }
    if host_lower.contains("lb") || host_lower.contains("loadbalancer") || host_lower.contains("haproxy") {
        return "load_balancer".to_string();
    }
    if host_lower.contains("storage") || host_lower.contains("nas") || host_lower.contains("san") {
        return "storage".to_string();
    }
    if host_lower.contains("k8s") || host_lower.contains("kube") || host_lower.contains("docker") || host_lower.contains("container") {
        return "container".to_string();
    }
    if host_lower.contains("vm-") || host_lower.contains("virtual") {
        return "virtual_machine".to_string();
    }

    // Check OS patterns
    if os_lower.contains("cisco") || os_lower.contains("juniper") {
        return "router".to_string();
    }
    if os_lower.contains("esxi") || os_lower.contains("vmware") || os_lower.contains("hyperv") {
        return "virtual_machine".to_string();
    }
    if os_lower.contains("windows") {
        // Check for server vs workstation
        if os_lower.contains("server") {
            return "server".to_string();
        }
        return "workstation".to_string();
    }
    if os_lower.contains("linux") || os_lower.contains("ubuntu") || os_lower.contains("centos") || os_lower.contains("rhel") || os_lower.contains("debian") {
        return "server".to_string();
    }
    if os_lower.contains("macos") || os_lower.contains("mac os") {
        return "laptop".to_string();
    }
    if os_lower.contains("android") || os_lower.contains("ios") {
        return "mobile".to_string();
    }

    // Check ports if available
    if let Some(ports) = ports {
        let has_db_port = ports.iter().any(|p| [3306, 5432, 1433, 1521, 27017].contains(&p.port));
        if has_db_port {
            return "database".to_string();
        }

        let has_web_port = ports.iter().any(|p| [80, 443, 8080, 8443].contains(&p.port));
        if has_web_port {
            return "server".to_string();
        }
    }

    // Default to server
    "server".to_string()
}

fn infer_security_zone(ip: &str) -> String {
    // Parse IP to determine zone based on RFC 1918 ranges and common patterns
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return "internal".to_string();
    }

    let first_octet: u8 = parts[0].parse().unwrap_or(0);
    let second_octet: u8 = parts[1].parse().unwrap_or(0);

    // 10.x.x.x - typically internal
    if first_octet == 10 {
        // 10.0.x.x - often DMZ
        if second_octet == 0 {
            return "dmz".to_string();
        }
        // 10.1.x.x - internal
        if second_octet == 1 {
            return "internal".to_string();
        }
        // 10.2.x.x - restricted/data
        if second_octet == 2 {
            return "restricted".to_string();
        }
        // 10.3.x.x - management
        if second_octet == 3 {
            return "management".to_string();
        }
        return "internal".to_string();
    }

    // 172.16-31.x.x - internal
    if first_octet == 172 && second_octet >= 16 && second_octet <= 31 {
        return "internal".to_string();
    }

    // 192.168.x.x - internal
    if first_octet == 192 && second_octet == 168 {
        return "internal".to_string();
    }

    // Everything else is external
    "external".to_string()
}

fn infer_network_connections(nodes: &[NetworkNode]) -> Vec<NetworkEdge> {
    let mut edges = Vec::new();

    // Group nodes by security zone
    let mut zone_nodes: HashMap<String, Vec<&NetworkNode>> = HashMap::new();
    for node in nodes {
        zone_nodes.entry(node.data.security_zone.clone()).or_default().push(node);
    }

    // Find potential gateway/firewall nodes
    let gateway_nodes: Vec<&NetworkNode> = nodes.iter()
        .filter(|n| ["firewall", "router", "vpn"].contains(&n.data.device_type.as_str()))
        .collect();

    // Connect hosts to their zone's gateway
    for node in nodes {
        if ["firewall", "router", "vpn"].contains(&node.data.device_type.as_str()) {
            continue;
        }

        // Find a gateway in the same zone or connect to a cross-zone firewall
        for gw in &gateway_nodes {
            if gw.data.security_zone == node.data.security_zone
               || gw.data.device_type == "firewall" {
                let edge_color = match node.data.security_zone.as_str() {
                    "external" => "#ef4444",
                    "dmz" => "#eab308",
                    "internal" => "#3b82f6",
                    "restricted" => "#a855f7",
                    "management" => "#22c55e",
                    _ => "#6b7280",
                };

                edges.push(NetworkEdge {
                    id: format!("e-{}-{}", gw.id, node.id),
                    source: gw.id.clone(),
                    target: node.id.clone(),
                    label: None,
                    animated: Some(false),
                    style: Some(EdgeStyle {
                        stroke: edge_color.to_string(),
                        stroke_width: None,
                        stroke_dasharray: None,
                    }),
                    marker_end: Some(MarkerEnd {
                        marker_type: "arrowclosed".to_string(),
                        color: edge_color.to_string(),
                    }),
                    data: None,
                });
                break;
            }
        }
    }

    // Connect gateways to each other (zone transitions)
    for (i, gw1) in gateway_nodes.iter().enumerate() {
        for gw2 in gateway_nodes.iter().skip(i + 1) {
            edges.push(NetworkEdge {
                id: format!("e-{}-{}", gw1.id, gw2.id),
                source: gw1.id.clone(),
                target: gw2.id.clone(),
                label: None,
                animated: Some(true),
                style: Some(EdgeStyle {
                    stroke: "#06b6d4".to_string(),
                    stroke_width: Some(2),
                    stroke_dasharray: None,
                }),
                marker_end: Some(MarkerEnd {
                    marker_type: "arrowclosed".to_string(),
                    color: "#06b6d4".to_string(),
                }),
                data: None,
            });
        }
    }

    edges
}

// ============================================================================
// Route Configuration
// ============================================================================

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/network-topology")
            .route("", web::get().to(get_topology))
            .route("", web::post().to(save_topology))
            .route("/list", web::get().to(list_topologies))
            .route("/{id}", web::delete().to(delete_topology))
            .route("/import/scan/{scan_id}", web::get().to(import_from_scan))
    );
}
