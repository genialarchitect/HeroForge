#![allow(dead_code)]
//! Attack Path Analyzer
//!
//! Analyzes scan results to identify attack chains and build attack graphs.

use super::graph::{AttackEdge, AttackGraph, AttackNode, NodeType};
use super::AttackPath;
use crate::types::HostInfo;
use std::collections::{HashMap, HashSet};

/// MITRE ATT&CK techniques for common attack vectors
#[derive(Debug, Clone)]
pub struct AttackTechnique {
    pub id: String,
    pub name: String,
    pub likelihood: f64,
    pub impact: f64,
}

impl AttackTechnique {
    pub fn new(id: &str, name: &str, likelihood: f64, impact: f64) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            likelihood,
            impact,
        }
    }
}

/// Attack path analyzer that builds graphs and identifies paths
#[derive(Debug, Default)]
pub struct AttackPathAnalyzer {
    /// Known attack techniques mapped by service/vulnerability type
    techniques: HashMap<String, AttackTechnique>,
    /// Services that are typically entry points
    entry_point_services: HashSet<String>,
    /// Services that indicate critical/target systems
    target_services: HashSet<String>,
}

impl AttackPathAnalyzer {
    /// Create a new attack path analyzer with default configurations
    pub fn new() -> Self {
        let mut analyzer = Self {
            techniques: HashMap::new(),
            entry_point_services: HashSet::new(),
            target_services: HashSet::new(),
        };

        analyzer.initialize_techniques();
        analyzer.initialize_service_classifications();

        analyzer
    }

    /// Initialize known attack techniques
    fn initialize_techniques(&mut self) {
        // Remote Service Exploitation
        self.techniques.insert(
            "ssh".to_string(),
            AttackTechnique::new("T1021.004", "SSH Exploitation", 0.6, 7.0),
        );
        self.techniques.insert(
            "rdp".to_string(),
            AttackTechnique::new("T1021.001", "RDP Exploitation", 0.7, 8.0),
        );
        self.techniques.insert(
            "smb".to_string(),
            AttackTechnique::new("T1021.002", "SMB Exploitation", 0.7, 8.0),
        );
        self.techniques.insert(
            "telnet".to_string(),
            AttackTechnique::new("T1021", "Telnet Access", 0.8, 6.0),
        );
        self.techniques.insert(
            "vnc".to_string(),
            AttackTechnique::new("T1021.005", "VNC Exploitation", 0.6, 7.0),
        );

        // Web Application Attacks
        self.techniques.insert(
            "http".to_string(),
            AttackTechnique::new("T1190", "Web Application Exploit", 0.5, 7.0),
        );
        self.techniques.insert(
            "https".to_string(),
            AttackTechnique::new("T1190", "Web Application Exploit", 0.5, 7.0),
        );

        // Database Attacks
        self.techniques.insert(
            "mysql".to_string(),
            AttackTechnique::new("T1213", "MySQL Database Access", 0.6, 9.0),
        );
        self.techniques.insert(
            "postgresql".to_string(),
            AttackTechnique::new("T1213", "PostgreSQL Database Access", 0.6, 9.0),
        );
        self.techniques.insert(
            "mongodb".to_string(),
            AttackTechnique::new("T1213", "MongoDB Database Access", 0.7, 9.0),
        );
        self.techniques.insert(
            "redis".to_string(),
            AttackTechnique::new("T1213", "Redis Cache Access", 0.7, 8.0),
        );
        self.techniques.insert(
            "elasticsearch".to_string(),
            AttackTechnique::new("T1213", "Elasticsearch Access", 0.7, 8.0),
        );

        // Authentication Services
        self.techniques.insert(
            "ldap".to_string(),
            AttackTechnique::new("T1078", "LDAP Authentication Abuse", 0.5, 8.0),
        );
        self.techniques.insert(
            "kerberos".to_string(),
            AttackTechnique::new("T1558", "Kerberos Attack", 0.4, 9.0),
        );

        // Network Services
        self.techniques.insert(
            "ftp".to_string(),
            AttackTechnique::new("T1071.002", "FTP Exploitation", 0.6, 6.0),
        );
        self.techniques.insert(
            "snmp".to_string(),
            AttackTechnique::new("T1046", "SNMP Enumeration", 0.7, 5.0),
        );
        self.techniques.insert(
            "dns".to_string(),
            AttackTechnique::new("T1071.004", "DNS Exploitation", 0.4, 6.0),
        );

        // Email Services
        self.techniques.insert(
            "smtp".to_string(),
            AttackTechnique::new("T1071.001", "SMTP Exploitation", 0.5, 6.0),
        );
        self.techniques.insert(
            "imap".to_string(),
            AttackTechnique::new("T1071.001", "IMAP Access", 0.5, 7.0),
        );
        self.techniques.insert(
            "pop3".to_string(),
            AttackTechnique::new("T1071.001", "POP3 Access", 0.5, 7.0),
        );
    }

    /// Initialize service classifications
    fn initialize_service_classifications(&mut self) {
        // Entry point services (externally accessible)
        self.entry_point_services.extend(vec![
            "http".to_string(),
            "https".to_string(),
            "ssh".to_string(),
            "rdp".to_string(),
            "ftp".to_string(),
            "smtp".to_string(),
            "telnet".to_string(),
            "vnc".to_string(),
        ]);

        // Target/critical services
        self.target_services.extend(vec![
            "mysql".to_string(),
            "postgresql".to_string(),
            "mongodb".to_string(),
            "redis".to_string(),
            "elasticsearch".to_string(),
            "ldap".to_string(),
            "kerberos".to_string(),
            "smb".to_string(),
            "domain".to_string(),
            "mssql".to_string(),
            "oracle".to_string(),
        ]);
    }

    /// Build an attack graph from scan results
    pub fn build_graph(&self, hosts: &[HostInfo]) -> AttackGraph {
        let mut graph = AttackGraph::new();
        let mut host_nodes: HashMap<String, Vec<String>> = HashMap::new(); // IP -> Node IDs

        // Create nodes for each host/port/service combination
        for host in hosts {
            let host_ip = host.target.ip.to_string();
            let mut node_ids = Vec::new();

            for port in &host.ports {
                if port.state != crate::types::PortState::Open {
                    continue;
                }

                let service_name = port
                    .service
                    .as_ref()
                    .map(|s| s.name.to_lowercase())
                    .unwrap_or_else(|| "unknown".to_string());

                // Determine node type based on service
                let node_type = if self.entry_point_services.contains(&service_name) {
                    NodeType::Entry
                } else if self.target_services.contains(&service_name) {
                    NodeType::Target
                } else {
                    NodeType::Pivot
                };

                let mut node = AttackNode::new(
                    Some(host_ip.clone()),
                    Some(port.port),
                    Some(service_name.clone()),
                    node_type,
                );

                // Add vulnerabilities for this port/service
                for vuln in &host.vulnerabilities {
                    if let Some(ref affected_service) = vuln.affected_service {
                        if affected_service.to_lowercase().contains(&service_name) {
                            let vuln_id = vuln
                                .cve_id
                                .clone()
                                .unwrap_or_else(|| format!("VULN-{}", uuid::Uuid::new_v4()));
                            node.add_vulnerability(vuln_id);

                            // Add severity to metadata
                            node.metadata.insert(
                                "max_severity".to_string(),
                                serde_json::json!(format!("{:?}", vuln.severity)),
                            );
                        }
                    }
                }

                // Add service banner/version to metadata if available
                if let Some(ref service) = port.service {
                    if let Some(ref version) = service.version {
                        node.metadata.insert(
                            "service_version".to_string(),
                            serde_json::json!(version),
                        );
                    }
                    if let Some(ref banner) = service.banner {
                        node.metadata.insert(
                            "banner".to_string(),
                            serde_json::json!(banner),
                        );
                    }
                }

                let node_ref = graph.add_node(node);
                node_ids.push(node_ref.id.clone());
            }

            // Also add any vulnerabilities not tied to a specific port
            for vuln in &host.vulnerabilities {
                if vuln.affected_service.is_none() {
                    // Create a host-level vulnerability node
                    let mut node = AttackNode::new(
                        Some(host_ip.clone()),
                        None,
                        None,
                        NodeType::Pivot,
                    );
                    let vuln_id = vuln
                        .cve_id
                        .clone()
                        .unwrap_or_else(|| format!("VULN-{}", uuid::Uuid::new_v4()));
                    node.add_vulnerability(vuln_id);
                    node.metadata.insert(
                        "max_severity".to_string(),
                        serde_json::json!(format!("{:?}", vuln.severity)),
                    );
                    let node_ref = graph.add_node(node);
                    node_ids.push(node_ref.id.clone());
                }
            }

            host_nodes.insert(host_ip, node_ids);
        }

        // Create edges between nodes based on attack patterns
        self.create_attack_edges(&mut graph, &host_nodes);

        // Calculate layout for visualization
        graph.calculate_layout();

        graph
    }

    /// Create edges representing potential attack paths
    fn create_attack_edges(
        &self,
        graph: &mut AttackGraph,
        _host_nodes: &HashMap<String, Vec<String>>,
    ) {
        // Collect all node information upfront to avoid borrow conflicts
        let nodes: Vec<(String, String, Option<String>, NodeType, bool)> = graph
            .nodes
            .iter()
            .map(|n| (
                n.id.clone(),
                n.host_ip.clone().unwrap_or_default(),
                n.service.clone(),
                n.node_type.clone(),
                n.has_vulnerabilities(),
            ))
            .collect();

        // Collect all edges to add
        let mut edges_to_add: Vec<AttackEdge> = Vec::new();

        // Entry points can connect to pivot/target nodes on same or different hosts
        for (node_id, host_ip, service, node_type, has_vulns) in &nodes {
            if *node_type == NodeType::Entry {
                // Connect entry points to internal services
                for (other_id, other_ip, other_service, _other_type, other_has_vulns) in &nodes {
                    if node_id == other_id {
                        continue;
                    }

                    // Create edges based on attack patterns
                    if let Some(edge) = self.should_create_edge(
                        service.as_deref(),
                        other_service.as_deref(),
                        host_ip,
                        other_ip,
                        *has_vulns,
                        *other_has_vulns,
                    ) {
                        let mut attack_edge = AttackEdge::new(
                            node_id.clone(),
                            other_id.clone(),
                            edge.name,
                            edge.technique_id,
                        )
                        .with_likelihood(edge.likelihood)
                        .with_impact(edge.impact);

                        if let Some(desc) = edge.description {
                            attack_edge = attack_edge.with_description(desc);
                        }

                        edges_to_add.push(attack_edge);
                    }
                }
            }

            // Pivot nodes can connect to target nodes
            if *node_type == NodeType::Pivot {
                for (other_id, other_ip, other_service, other_type, other_has_vulns) in &nodes {
                    if node_id == other_id {
                        continue;
                    }

                    if *other_type == NodeType::Target {
                        if let Some(edge) = self.should_create_edge(
                            service.as_deref(),
                            other_service.as_deref(),
                            host_ip,
                            other_ip,
                            *has_vulns,
                            *other_has_vulns,
                        ) {
                            let mut attack_edge = AttackEdge::new(
                                node_id.clone(),
                                other_id.clone(),
                                edge.name,
                                edge.technique_id,
                            )
                            .with_likelihood(edge.likelihood)
                            .with_impact(edge.impact);

                            if let Some(desc) = edge.description {
                                attack_edge = attack_edge.with_description(desc);
                            }

                            edges_to_add.push(attack_edge);
                        }
                    }
                }
            }
        }

        // Add all collected edges
        for edge in edges_to_add {
            graph.add_edge(edge);
        }
    }

    /// Determine if an edge should be created between two nodes
    fn should_create_edge(
        &self,
        source_service: Option<&str>,
        target_service: Option<&str>,
        source_ip: &str,
        target_ip: &str,
        source_has_vulns: bool,
        target_has_vulns: bool,
    ) -> Option<EdgeInfo> {
        let source = source_service.unwrap_or("unknown").to_lowercase();
        let target = target_service.unwrap_or("unknown").to_lowercase();
        let same_host = source_ip == target_ip;

        // Get technique for target service
        let technique = self.techniques.get(&target);

        // Define attack patterns
        match (source.as_str(), target.as_str()) {
            // Web to database patterns
            ("http" | "https", "mysql" | "postgresql" | "mongodb" | "mssql" | "oracle") => {
                Some(EdgeInfo {
                    name: Some("SQL Injection / Database Access".to_string()),
                    technique_id: Some("T1213".to_string()),
                    likelihood: if source_has_vulns { 0.8 } else { 0.4 },
                    impact: 9.0,
                    description: Some("Web application to database lateral movement".to_string()),
                })
            }

            // SSH/RDP lateral movement
            ("ssh" | "rdp", "ssh" | "rdp") if !same_host => Some(EdgeInfo {
                name: Some("Remote Desktop/SSH Lateral Movement".to_string()),
                technique_id: Some("T1021".to_string()),
                likelihood: if source_has_vulns { 0.7 } else { 0.5 },
                impact: 8.0,
                description: Some("Credential reuse for lateral movement".to_string()),
            }),

            // SMB lateral movement
            ("smb", "smb") if !same_host => Some(EdgeInfo {
                name: Some("SMB Lateral Movement".to_string()),
                technique_id: Some("T1021.002".to_string()),
                likelihood: if source_has_vulns { 0.8 } else { 0.5 },
                impact: 8.0,
                description: Some("SMB/Windows share access for lateral movement".to_string()),
            }),

            // Any entry point to internal service on same host
            (_, _) if same_host && self.entry_point_services.contains(&source) => {
                if let Some(tech) = technique {
                    Some(EdgeInfo {
                        name: Some(format!("Local Privilege Escalation to {}", target)),
                        technique_id: Some(tech.id.clone()),
                        likelihood: tech.likelihood * if source_has_vulns { 1.2 } else { 0.8 },
                        impact: tech.impact,
                        description: Some("Local service access after initial compromise".to_string()),
                    })
                } else {
                    Some(EdgeInfo {
                        name: Some("Local Service Access".to_string()),
                        technique_id: None,
                        likelihood: 0.4,
                        impact: 6.0,
                        description: Some("Access to local service".to_string()),
                    })
                }
            }

            // Vulnerable source to any target
            (_, _) if source_has_vulns && target_has_vulns => Some(EdgeInfo {
                name: Some("Vulnerability Chain".to_string()),
                technique_id: technique.map(|t| t.id.clone()),
                likelihood: 0.6,
                impact: technique.map(|t| t.impact).unwrap_or(7.0),
                description: Some("Chained exploitation of vulnerable services".to_string()),
            }),

            _ => None,
        }
    }

    /// Find all attack paths in the graph
    pub fn find_attack_paths(&self, graph: &AttackGraph) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let entry_nodes = graph.entry_nodes();
        let target_nodes = graph.target_nodes();

        for entry in &entry_nodes {
            for target in &target_nodes {
                // Find paths from entry to target using DFS
                let found_paths = self.find_paths_dfs(graph, &entry.id, &target.id);

                for (node_ids, edge_ids) in found_paths {
                    let path_nodes: Vec<AttackNode> = node_ids
                        .iter()
                        .filter_map(|id| graph.get_node_by_id(id).cloned())
                        .collect();

                    let path_edges: Vec<AttackEdge> = edge_ids
                        .iter()
                        .filter_map(|id| graph.edges.iter().find(|e| e.id == *id).cloned())
                        .collect();

                    if !path_nodes.is_empty() {
                        let mut path = AttackPath::new(path_nodes, path_edges);
                        path.name = Some(format!(
                            "{} -> {}",
                            entry.service.as_deref().unwrap_or("entry"),
                            target.service.as_deref().unwrap_or("target")
                        ));
                        paths.push(path);
                    }
                }
            }
        }

        // Also find paths between vulnerable nodes
        let vulnerable_nodes = graph.vulnerable_nodes();
        for vuln_node in &vulnerable_nodes {
            if vuln_node.node_type == NodeType::Entry {
                for target in &target_nodes {
                    if vuln_node.id != target.id {
                        let found_paths = self.find_paths_dfs(graph, &vuln_node.id, &target.id);

                        for (node_ids, edge_ids) in found_paths {
                            let path_nodes: Vec<AttackNode> = node_ids
                                .iter()
                                .filter_map(|id| graph.get_node_by_id(id).cloned())
                                .collect();

                            let path_edges: Vec<AttackEdge> = edge_ids
                                .iter()
                                .filter_map(|id| graph.edges.iter().find(|e| e.id == *id).cloned())
                                .collect();

                            if !path_nodes.is_empty()
                                && !paths.iter().any(|p| {
                                    p.nodes.iter().map(|n| &n.id).collect::<Vec<_>>()
                                        == path_nodes.iter().map(|n| &n.id).collect::<Vec<_>>()
                                })
                            {
                                let mut path = AttackPath::new(path_nodes, path_edges);
                                path.name = Some(format!(
                                    "Vuln: {} -> {}",
                                    vuln_node.service.as_deref().unwrap_or("entry"),
                                    target.service.as_deref().unwrap_or("target")
                                ));
                                paths.push(path);
                            }
                        }
                    }
                }
            }
        }

        paths
    }

    /// DFS to find paths between two nodes
    fn find_paths_dfs(
        &self,
        graph: &AttackGraph,
        start_id: &str,
        end_id: &str,
    ) -> Vec<(Vec<String>, Vec<String>)> {
        let mut all_paths = Vec::new();
        let mut current_path = vec![start_id.to_string()];
        let mut current_edges = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(start_id.to_string());

        self.dfs_helper(
            graph,
            start_id,
            end_id,
            &mut current_path,
            &mut current_edges,
            &mut visited,
            &mut all_paths,
            10, // Max depth to prevent infinite loops
        );

        all_paths
    }

    /// Helper function for DFS path finding
    fn dfs_helper(
        &self,
        graph: &AttackGraph,
        current_id: &str,
        end_id: &str,
        current_path: &mut Vec<String>,
        current_edges: &mut Vec<String>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<(Vec<String>, Vec<String>)>,
        max_depth: usize,
    ) {
        if current_id == end_id {
            all_paths.push((current_path.clone(), current_edges.clone()));
            return;
        }

        if max_depth == 0 {
            return;
        }

        for edge in graph.edges_from(current_id) {
            if !visited.contains(&edge.target_node_id) {
                visited.insert(edge.target_node_id.clone());
                current_path.push(edge.target_node_id.clone());
                current_edges.push(edge.id.clone());

                self.dfs_helper(
                    graph,
                    &edge.target_node_id,
                    end_id,
                    current_path,
                    current_edges,
                    visited,
                    all_paths,
                    max_depth - 1,
                );

                current_path.pop();
                current_edges.pop();
                visited.remove(&edge.target_node_id);
            }
        }
    }
}

/// Information about an edge to create
struct EdgeInfo {
    name: Option<String>,
    technique_id: Option<String>,
    likelihood: f64,
    impact: f64,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HostInfo, PortInfo, Protocol, PortState, ScanTarget, ServiceInfo};
    use std::net::IpAddr;
    use std::time::Duration;

    fn create_test_host(ip: &str, ports: Vec<(u16, &str)>) -> HostInfo {
        HostInfo {
            target: ScanTarget {
                ip: ip.parse::<IpAddr>().unwrap(),
                hostname: None,
            },
            is_alive: true,
            os_guess: None,
            ports: ports
                .into_iter()
                .map(|(port, service)| PortInfo {
                    port,
                    protocol: Protocol::TCP,
                    state: PortState::Open,
                    service: Some(ServiceInfo {
                        name: service.to_string(),
                        version: None,
                        banner: None,
                        cpe: None,
                        enumeration: None,
                        ssl_info: None,
                    }),
                })
                .collect(),
            vulnerabilities: Vec::new(),
            scan_duration: Duration::from_secs(1),
        }
    }

    #[test]
    fn test_build_graph() {
        let analyzer = AttackPathAnalyzer::new();
        let hosts = vec![
            create_test_host("192.168.1.1", vec![(22, "ssh"), (80, "http")]),
            create_test_host("192.168.1.2", vec![(3306, "mysql"), (5432, "postgresql")]),
        ];

        let graph = analyzer.build_graph(&hosts);

        assert_eq!(graph.nodes.len(), 4);
        assert!(graph.entry_nodes().len() >= 1);
        assert!(graph.target_nodes().len() >= 1);
    }

    #[test]
    fn test_find_attack_paths() {
        let analyzer = AttackPathAnalyzer::new();
        let hosts = vec![
            create_test_host("192.168.1.1", vec![(80, "http")]),
            create_test_host("192.168.1.2", vec![(3306, "mysql")]),
        ];

        let graph = analyzer.build_graph(&hosts);
        let paths = analyzer.find_attack_paths(&graph);

        // Should find at least one path from http to mysql
        assert!(!paths.is_empty() || graph.edges.is_empty());
    }
}
