use actix_web::{web, HttpResponse, Result};
use sqlx::SqlitePool;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::db;
use crate::types::{HostInfo, Severity};
use crate::web::auth;

/// Node in the network topology graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub os_family: Option<String>,
    pub risk_score: f32,
    pub open_ports_count: usize,
    pub vuln_count: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
    pub subnet: String,
    pub is_gateway: bool,
    pub node_type: NodeType,
}

/// Edge representing a relationship between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub relationship_type: RelationType,
    pub strength: f32, // 0.0-1.0 indicating relationship strength
}

/// Type of node for visual representation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeType {
    Server,
    Workstation,
    Network,
    Unknown,
    Gateway,
}

/// Type of relationship between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationType {
    SameSubnet,
    SharedService,
    Gateway,
}

/// Subnet group for clustering nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetGroup {
    pub subnet: String,
    pub nodes: Vec<String>, // Node IDs
    pub host_count: usize,
}

/// Complete topology response
#[derive(Debug, Serialize, Deserialize)]
pub struct TopologyResponse {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
    pub subnets: Vec<SubnetGroup>,
}

/// GET /api/scans/{id}/topology - Get network topology for a scan
pub async fn get_scan_topology(
    pool: web::Data<SqlitePool>,
    claims: web::ReqData<auth::Claims>,
    scan_id: web::Path<String>,
) -> Result<HttpResponse> {
    // Fetch scan and verify ownership
    let scan = db::get_scan_by_id(&pool, &scan_id)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Failed to fetch scan"))?;

    let scan = match scan {
        Some(s) => {
            if s.user_id != claims.sub {
                return Ok(HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Access denied"
                })));
            }
            s
        }
        None => {
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Scan not found"
            })));
        }
    };

    // Check if scan has results
    let results_json = match scan.results {
        Some(r) => r,
        None => {
            return Ok(HttpResponse::Ok().json(TopologyResponse {
                nodes: vec![],
                edges: vec![],
                subnets: vec![],
            }));
        }
    };

    // Parse scan results
    let hosts: Vec<HostInfo> = serde_json::from_str(&results_json)
        .map_err(|e| {
            log::error!("Failed to parse scan results: {}", e);
            actix_web::error::ErrorInternalServerError("Invalid scan results format")
        })?;

    // Generate topology
    let topology = generate_topology(&hosts);

    Ok(HttpResponse::Ok().json(topology))
}

/// Generate network topology from scan results
fn generate_topology(hosts: &[HostInfo]) -> TopologyResponse {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut subnet_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut service_map: HashMap<String, HashSet<String>> = HashMap::new(); // service -> node IDs

    // Create nodes
    for host in hosts {
        if !host.is_alive {
            continue;
        }

        let ip = host.target.ip.to_string();
        let subnet = get_subnet(&host.target.ip);

        // Calculate risk score based on vulnerabilities
        let (risk_score, critical_vulns, high_vulns) = calculate_risk_score(&host.vulnerabilities);

        // Determine node type based on OS and open ports
        let node_type = determine_node_type(host);

        let node = TopologyNode {
            id: ip.clone(),
            ip: ip.clone(),
            hostname: host.target.hostname.clone(),
            os: host.os_guess.as_ref().map(|os| format!(
                "{} {}",
                os.os_family,
                os.os_version.as_deref().unwrap_or("")
            ).trim().to_string()),
            os_family: host.os_guess.as_ref().map(|os| os.os_family.clone()),
            risk_score,
            open_ports_count: host.ports.iter().filter(|p| {
                matches!(p.state, crate::types::PortState::Open)
            }).count(),
            vuln_count: host.vulnerabilities.len(),
            critical_vulns,
            high_vulns,
            subnet: subnet.clone(),
            is_gateway: false, // Will be updated later
            node_type,
        };

        // Track subnet membership
        subnet_map.entry(subnet.clone())
            .or_insert_with(Vec::new)
            .push(ip.clone());

        // Track services for relationship detection
        for port in &host.ports {
            if let Some(service) = &port.service {
                let service_key = format!("{}:{}", service.name, port.port);
                service_map.entry(service_key)
                    .or_insert_with(HashSet::new)
                    .insert(ip.clone());
            }
        }

        nodes.push(node);
    }

    // Detect gateways (hosts with many connections or specific characteristics)
    let gateways = detect_gateways(hosts);
    for node in &mut nodes {
        if gateways.contains(&node.ip) {
            node.is_gateway = true;
            node.node_type = NodeType::Gateway;
        }
    }

    // Create same-subnet edges
    for (_subnet, node_ids) in &subnet_map {
        if node_ids.len() > 1 {
            // For each subnet, connect nodes to potential gateway or create mesh
            if let Some(gateway_ip) = find_subnet_gateway(node_ids, &gateways) {
                // Connect all nodes to gateway
                for node_id in node_ids {
                    if node_id != gateway_ip {
                        edges.push(TopologyEdge {
                            source: gateway_ip.clone(),
                            target: node_id.clone(),
                            relationship_type: RelationType::Gateway,
                            strength: 0.9,
                        });
                    }
                }
            } else {
                // Create limited mesh within subnet (connect each to nearest neighbors)
                for i in 0..node_ids.len().min(3) {
                    for j in (i + 1)..node_ids.len().min(i + 3) {
                        edges.push(TopologyEdge {
                            source: node_ids[i].clone(),
                            target: node_ids[j].clone(),
                            relationship_type: RelationType::SameSubnet,
                            strength: 0.5,
                        });
                    }
                }
            }
        }
    }

    // Create shared-service edges
    for (service_name, node_ids) in &service_map {
        if node_ids.len() > 1 && node_ids.len() <= 5 {
            // Only create service edges for uncommon services shared by few hosts
            let is_common_service = service_name.starts_with("http:") ||
                                   service_name.starts_with("https:");

            if !is_common_service {
                let nodes_vec: Vec<_> = node_ids.iter().collect();
                for i in 0..nodes_vec.len() {
                    for j in (i + 1)..nodes_vec.len() {
                        // Avoid duplicate edges
                        let edge_exists = edges.iter().any(|e| {
                            (e.source == *nodes_vec[i] && e.target == *nodes_vec[j]) ||
                            (e.source == *nodes_vec[j] && e.target == *nodes_vec[i])
                        });

                        if !edge_exists {
                            edges.push(TopologyEdge {
                                source: nodes_vec[i].to_string(),
                                target: nodes_vec[j].to_string(),
                                relationship_type: RelationType::SharedService,
                                strength: 0.3,
                            });
                        }
                    }
                }
            }
        }
    }

    // Create subnet groups
    let subnets: Vec<SubnetGroup> = subnet_map
        .into_iter()
        .map(|(subnet, nodes)| SubnetGroup {
            host_count: nodes.len(),
            subnet,
            nodes,
        })
        .collect();

    TopologyResponse {
        nodes,
        edges,
        subnets,
    }
}

/// Calculate risk score from vulnerabilities
fn calculate_risk_score(vulnerabilities: &[crate::types::Vulnerability]) -> (f32, usize, usize) {
    let mut score = 0.0;
    let mut critical_count = 0;
    let mut high_count = 0;

    for vuln in vulnerabilities {
        let weight = match vuln.severity {
            Severity::Critical => {
                critical_count += 1;
                10.0
            }
            Severity::High => {
                high_count += 1;
                5.0
            }
            Severity::Medium => 2.0,
            Severity::Low => 0.5,
        };
        score += weight;
    }

    // Normalize score to 0-100 range
    let normalized = (score / (vulnerabilities.len().max(1) as f32 * 10.0) * 100.0).min(100.0);

    (normalized, critical_count, high_count)
}

/// Determine node type based on characteristics
fn determine_node_type(host: &HostInfo) -> NodeType {
    // Check OS family
    if let Some(os) = &host.os_guess {
        let os_lower = os.os_family.to_lowercase();
        if os_lower.contains("linux") || os_lower.contains("unix") || os_lower.contains("windows server") {
            return NodeType::Server;
        }
        if os_lower.contains("windows") {
            return NodeType::Workstation;
        }
    }

    // Check services to infer type
    let open_ports: Vec<_> = host.ports.iter()
        .filter(|p| matches!(p.state, crate::types::PortState::Open))
        .collect();

    // Server indicators: common server ports
    let server_ports = [22, 23, 25, 80, 443, 3306, 5432, 8080, 8443];
    let has_server_ports = open_ports.iter().any(|p| server_ports.contains(&p.port));

    if has_server_ports {
        return NodeType::Server;
    }

    // Many open ports might indicate network device
    if open_ports.len() > 20 {
        return NodeType::Network;
    }

    NodeType::Unknown
}

/// Get subnet from IP address (Class C subnet)
fn get_subnet(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ipv6) => {
            // For IPv6, use /64 subnet
            let segments = ipv6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", segments[0], segments[1], segments[2], segments[3])
        }
    }
}

/// Detect potential gateway hosts
fn detect_gateways(hosts: &[HostInfo]) -> HashSet<String> {
    let mut gateways = HashSet::new();

    for host in hosts {
        if !host.is_alive {
            continue;
        }

        let ip = host.target.ip.to_string();

        // Gateway indicators:
        // 1. IP ending in .1, .254, or .255 (common gateway addresses)
        if let IpAddr::V4(ipv4) = host.target.ip {
            let last_octet = ipv4.octets()[3];
            if last_octet == 1 || last_octet == 254 || last_octet == 255 {
                gateways.insert(ip.clone());
                continue;
            }
        }

        // 2. Many open ports (routers often have many services)
        let open_count = host.ports.iter()
            .filter(|p| matches!(p.state, crate::types::PortState::Open))
            .count();

        if open_count > 15 {
            gateways.insert(ip.clone());
            continue;
        }

        // 3. Network device OS detection
        if let Some(os) = &host.os_guess {
            let os_lower = os.os_family.to_lowercase();
            if os_lower.contains("router") ||
               os_lower.contains("firewall") ||
               os_lower.contains("cisco") ||
               os_lower.contains("juniper") {
                gateways.insert(ip);
                continue;
            }
        }
    }

    gateways
}

/// Find gateway in a subnet
fn find_subnet_gateway<'a>(node_ids: &'a [String], gateways: &'a HashSet<String>) -> Option<&'a String> {
    // Return first gateway found in this subnet
    node_ids.iter().find(|id| gateways.contains(*id))
}
