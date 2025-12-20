//! Attack Graph Data Structure
//!
//! Provides graph-based representation of attack paths through a network.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of node in the attack graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Entry point - externally accessible host
    Entry,
    /// Pivot point - intermediate host for lateral movement
    Pivot,
    /// Target - critical asset or destination
    Target,
}

impl NodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeType::Entry => "entry",
            NodeType::Pivot => "pivot",
            NodeType::Target => "target",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "entry" => Some(NodeType::Entry),
            "pivot" => Some(NodeType::Pivot),
            "target" => Some(NodeType::Target),
            _ => None,
        }
    }
}

/// A node in the attack graph representing a host/service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: String,
    pub host_ip: Option<String>,
    pub port: Option<u16>,
    pub service: Option<String>,
    pub vulnerability_ids: Vec<String>,
    pub node_type: NodeType,
    pub position_x: f64,
    pub position_y: f64,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AttackNode {
    /// Create a new attack node
    pub fn new(
        host_ip: Option<String>,
        port: Option<u16>,
        service: Option<String>,
        node_type: NodeType,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            host_ip,
            port,
            service,
            vulnerability_ids: Vec::new(),
            node_type,
            position_x: 0.0,
            position_y: 0.0,
            metadata: HashMap::new(),
        }
    }

    /// Add a vulnerability to this node
    pub fn add_vulnerability(&mut self, vuln_id: String) {
        if !self.vulnerability_ids.contains(&vuln_id) {
            self.vulnerability_ids.push(vuln_id);
        }
    }

    /// Get a unique key for this node
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.host_ip.as_deref().unwrap_or("unknown"),
            self.port.map(|p| p.to_string()).unwrap_or_else(|| "0".to_string()),
            self.service.as_deref().unwrap_or("unknown")
        )
    }

    /// Check if this node has vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerability_ids.is_empty()
    }

    /// Get the number of vulnerabilities
    pub fn vulnerability_count(&self) -> usize {
        self.vulnerability_ids.len()
    }
}

/// An edge in the attack graph representing a connection between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub attack_technique: Option<String>,
    pub technique_id: Option<String>,
    pub likelihood: f64,
    pub impact: f64,
    pub description: Option<String>,
}

impl AttackEdge {
    /// Create a new attack edge
    pub fn new(
        source_node_id: String,
        target_node_id: String,
        attack_technique: Option<String>,
        technique_id: Option<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_node_id,
            target_node_id,
            attack_technique,
            technique_id,
            likelihood: 0.5,
            impact: 5.0,
            description: None,
        }
    }

    /// Set the likelihood of successful exploitation
    pub fn with_likelihood(mut self, likelihood: f64) -> Self {
        self.likelihood = likelihood.clamp(0.0, 1.0);
        self
    }

    /// Set the impact score (0-10)
    pub fn with_impact(mut self, impact: f64) -> Self {
        self.impact = impact.clamp(0.0, 10.0);
        self
    }

    /// Set the description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
}

/// The complete attack graph structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackGraph {
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    node_index: HashMap<String, usize>,
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGraph {
    /// Create a new empty attack graph
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            node_index: HashMap::new(),
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, node: AttackNode) -> &AttackNode {
        let key = node.key();
        let index = self.nodes.len();
        self.node_index.insert(key, index);
        self.nodes.push(node);
        &self.nodes[index]
    }

    /// Get a node by its key
    pub fn get_node(&self, key: &str) -> Option<&AttackNode> {
        self.node_index.get(key).map(|&idx| &self.nodes[idx])
    }

    /// Get a node by its ID
    pub fn get_node_by_id(&self, id: &str) -> Option<&AttackNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Get a mutable reference to a node by its key
    pub fn get_node_mut(&mut self, key: &str) -> Option<&mut AttackNode> {
        self.node_index.get(key).map(|&idx| &mut self.nodes[idx])
    }

    /// Add an edge to the graph
    pub fn add_edge(&mut self, edge: AttackEdge) {
        self.edges.push(edge);
    }

    /// Get all edges from a specific node
    pub fn edges_from(&self, node_id: &str) -> Vec<&AttackEdge> {
        self.edges
            .iter()
            .filter(|e| e.source_node_id == node_id)
            .collect()
    }

    /// Get all edges to a specific node
    pub fn edges_to(&self, node_id: &str) -> Vec<&AttackEdge> {
        self.edges
            .iter()
            .filter(|e| e.target_node_id == node_id)
            .collect()
    }

    /// Get all entry point nodes
    pub fn entry_nodes(&self) -> Vec<&AttackNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Entry)
            .collect()
    }

    /// Get all target nodes
    pub fn target_nodes(&self) -> Vec<&AttackNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Target)
            .collect()
    }

    /// Get all nodes with vulnerabilities
    pub fn vulnerable_nodes(&self) -> Vec<&AttackNode> {
        self.nodes
            .iter()
            .filter(|n| n.has_vulnerabilities())
            .collect()
    }

    /// Get adjacent nodes for a given node
    pub fn adjacent_nodes(&self, node_id: &str) -> Vec<&AttackNode> {
        let target_ids: Vec<&str> = self
            .edges_from(node_id)
            .iter()
            .map(|e| e.target_node_id.as_str())
            .collect();

        self.nodes
            .iter()
            .filter(|n| target_ids.contains(&n.id.as_str()))
            .collect()
    }

    /// Calculate layout positions for visualization
    pub fn calculate_layout(&mut self) {
        // Simple layered layout algorithm
        // Layer 0: Entry nodes
        // Layer 1+: Reachable nodes by distance
        let mut visited: HashMap<String, usize> = HashMap::new();
        let mut queue: Vec<(String, usize)> = Vec::new();

        // Start with entry nodes at layer 0
        for node in self.entry_nodes() {
            visited.insert(node.id.clone(), 0);
            queue.push((node.id.clone(), 0));
        }

        // BFS to assign layers
        while let Some((node_id, layer)) = queue.pop() {
            for edge in self.edges_from(&node_id) {
                if !visited.contains_key(&edge.target_node_id) {
                    visited.insert(edge.target_node_id.clone(), layer + 1);
                    queue.push((edge.target_node_id.clone(), layer + 1));
                }
            }
        }

        // Group nodes by layer
        let mut layers: HashMap<usize, Vec<String>> = HashMap::new();
        for (node_id, layer) in &visited {
            layers.entry(*layer).or_default().push(node_id.clone());
        }

        // Assign positions
        let layer_width = 200.0;
        for (layer, node_ids) in layers {
            let node_count = node_ids.len();
            for (idx, node_id) in node_ids.into_iter().enumerate() {
                if let Some(node) = self.nodes.iter_mut().find(|n| n.id == node_id) {
                    node.position_x = layer as f64 * layer_width;
                    node.position_y = (idx as f64 - node_count as f64 / 2.0) * 100.0;
                }
            }
        }

        // Handle unvisited nodes (disconnected components)
        let max_layer = visited.values().max().copied().unwrap_or(0);
        let mut unvisited_idx = 0;
        for node in &mut self.nodes {
            if !visited.contains_key(&node.id) {
                node.position_x = (max_layer + 1) as f64 * layer_width;
                node.position_y = unvisited_idx as f64 * 100.0;
                unvisited_idx += 1;
            }
        }
    }

    /// Get statistics about the graph
    pub fn stats(&self) -> GraphStats {
        GraphStats {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            entry_nodes: self.nodes.iter().filter(|n| n.node_type == NodeType::Entry).count(),
            pivot_nodes: self.nodes.iter().filter(|n| n.node_type == NodeType::Pivot).count(),
            target_nodes: self.nodes.iter().filter(|n| n.node_type == NodeType::Target).count(),
            vulnerable_nodes: self.nodes.iter().filter(|n| n.has_vulnerabilities()).count(),
            total_vulnerabilities: self.nodes.iter().map(|n| n.vulnerability_count()).sum(),
        }
    }
}

/// Statistics about an attack graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub entry_nodes: usize,
    pub pivot_nodes: usize,
    pub target_nodes: usize,
    pub vulnerable_nodes: usize,
    pub total_vulnerabilities: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        let node = AttackNode::new(
            Some("192.168.1.1".to_string()),
            Some(22),
            Some("ssh".to_string()),
            NodeType::Entry,
        );

        assert_eq!(node.host_ip, Some("192.168.1.1".to_string()));
        assert_eq!(node.port, Some(22));
        assert_eq!(node.service, Some("ssh".to_string()));
        assert_eq!(node.node_type, NodeType::Entry);
    }

    #[test]
    fn test_graph_operations() {
        let mut graph = AttackGraph::new();

        let node1 = AttackNode::new(
            Some("192.168.1.1".to_string()),
            Some(22),
            Some("ssh".to_string()),
            NodeType::Entry,
        );
        let node1_id = node1.id.clone();
        graph.add_node(node1);

        let node2 = AttackNode::new(
            Some("192.168.1.2".to_string()),
            Some(3389),
            Some("rdp".to_string()),
            NodeType::Target,
        );
        let node2_id = node2.id.clone();
        graph.add_node(node2);

        let edge = AttackEdge::new(
            node1_id.clone(),
            node2_id.clone(),
            Some("Lateral Movement".to_string()),
            Some("T1021".to_string()),
        );
        graph.add_edge(edge);

        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.entry_nodes().len(), 1);
        assert_eq!(graph.target_nodes().len(), 1);
    }
}
