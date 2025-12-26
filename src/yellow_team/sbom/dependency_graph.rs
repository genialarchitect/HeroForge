//! Dependency Graph Analysis
//!
//! Analyzes transitive dependencies and identifies potential issues
//! like circular dependencies, version conflicts, and outdated packages.

use crate::yellow_team::types::*;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

/// Dependency graph representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// All nodes (components) in the graph
    pub nodes: Vec<DependencyNode>,
    /// Edges (dependency relationships)
    pub edges: Vec<DependencyEdge>,
    /// Graph statistics
    pub stats: GraphStats,
    /// Detected issues
    pub issues: Vec<DependencyIssue>,
}

/// A node in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    /// Component ID
    pub id: String,
    /// Component name
    pub name: String,
    /// Component version
    pub version: String,
    /// Whether this is a direct dependency
    pub is_direct: bool,
    /// Depth in the dependency tree
    pub depth: u32,
    /// Number of dependents (how many packages depend on this)
    pub dependent_count: u32,
    /// Number of dependencies (how many packages this depends on)
    pub dependency_count: u32,
}

/// An edge in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Source component ID
    pub from: String,
    /// Target component ID
    pub to: String,
    /// Dependency type
    pub dependency_type: DependencyType,
    /// Version constraint (if known)
    pub version_constraint: Option<String>,
}

/// Type of dependency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyType {
    /// Runtime dependency
    Runtime,
    /// Development dependency
    Development,
    /// Build dependency
    Build,
    /// Optional dependency
    Optional,
    /// Peer dependency
    Peer,
}

/// Graph statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    /// Total number of components
    pub total_nodes: u32,
    /// Total number of edges
    pub total_edges: u32,
    /// Direct dependencies count
    pub direct_dependencies: u32,
    /// Transitive dependencies count
    pub transitive_dependencies: u32,
    /// Maximum depth of dependency tree
    pub max_depth: u32,
    /// Average depth
    pub avg_depth: f64,
    /// Most depended-upon packages
    pub most_depended: Vec<(String, u32)>,
    /// Packages with most dependencies
    pub most_dependencies: Vec<(String, u32)>,
}

/// Issue detected in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyIssue {
    /// Issue type
    pub issue_type: DependencyIssueType,
    /// Severity
    pub severity: Severity,
    /// Affected components
    pub components: Vec<String>,
    /// Issue description
    pub description: String,
    /// Recommended action
    pub recommendation: String,
}

/// Types of dependency issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyIssueType {
    /// Circular dependency detected
    CircularDependency,
    /// Version conflict between packages
    VersionConflict,
    /// Multiple versions of same package
    DuplicatePackage,
    /// Package appears to be abandoned (very old)
    PotentiallyAbandoned,
    /// Deep dependency chain (potential supply chain risk)
    DeepDependencyChain,
    /// Package has too many dependencies
    HighDependencyCount,
    /// Package is depended upon by many (high risk if compromised)
    HighDependentCount,
    /// License incompatibility
    LicenseIncompatibility,
}

impl DependencyGraph {
    /// Create an empty dependency graph
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            stats: GraphStats {
                total_nodes: 0,
                total_edges: 0,
                direct_dependencies: 0,
                transitive_dependencies: 0,
                max_depth: 0,
                avg_depth: 0.0,
                most_depended: Vec::new(),
                most_dependencies: Vec::new(),
            },
            issues: Vec::new(),
        }
    }

    /// Create from components and dependency map
    pub fn from_components(
        components: &[SbomComponent],
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Self {
        let mut graph = Self::new();
        
        // Create nodes
        for component in components {
            let dependent_count = dependencies.values()
                .filter(|deps| deps.contains(&component.id))
                .count() as u32;
            
            let dependency_count = dependencies.get(&component.id)
                .map(|d| d.len() as u32)
                .unwrap_or(0);
            
            graph.nodes.push(DependencyNode {
                id: component.id.clone(),
                name: component.name.clone(),
                version: component.version.clone(),
                is_direct: component.is_direct(),
                depth: if component.is_direct() { 1 } else { 2 }, // Will be updated
                dependent_count,
                dependency_count,
            });
        }
        
        // Create edges
        for (from, to_list) in dependencies {
            for to in to_list {
                graph.edges.push(DependencyEdge {
                    from: from.clone(),
                    to: to.clone(),
                    dependency_type: DependencyType::Runtime,
                    version_constraint: None,
                });
            }
        }
        
        // Calculate depths using BFS
        graph.calculate_depths();
        
        // Calculate statistics
        graph.calculate_stats();
        
        // Detect issues
        graph.detect_issues();
        
        graph
    }

    /// Calculate depths of all nodes using BFS
    fn calculate_depths(&mut self) {
        // Build adjacency list with owned strings
        let adj: HashMap<String, Vec<String>> = self.edges.iter()
            .fold(HashMap::new(), |mut acc, edge| {
                acc.entry(edge.from.clone()).or_default().push(edge.to.clone());
                acc
            });

        // Find root nodes (direct dependencies) - collect owned strings
        let roots: Vec<String> = self.nodes.iter()
            .filter(|n| n.is_direct)
            .map(|n| n.id.clone())
            .collect();

        // BFS from roots with owned strings
        let mut depths: HashMap<String, u32> = HashMap::new();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();

        for root in roots {
            depths.insert(root.clone(), 1);
            queue.push_back((root, 1));
        }

        while let Some((node, depth)) = queue.pop_front() {
            if let Some(neighbors) = adj.get(&node) {
                for neighbor in neighbors {
                    if !depths.contains_key(neighbor) {
                        depths.insert(neighbor.clone(), depth + 1);
                        queue.push_back((neighbor.clone(), depth + 1));
                    }
                }
            }
        }

        // Update node depths
        for node in &mut self.nodes {
            if let Some(&depth) = depths.get(&node.id) {
                node.depth = depth;
            }
        }
    }

    /// Calculate graph statistics
    fn calculate_stats(&mut self) {
        self.stats.total_nodes = self.nodes.len() as u32;
        self.stats.total_edges = self.edges.len() as u32;
        self.stats.direct_dependencies = self.nodes.iter().filter(|n| n.is_direct).count() as u32;
        self.stats.transitive_dependencies = self.stats.total_nodes - self.stats.direct_dependencies;
        
        if !self.nodes.is_empty() {
            self.stats.max_depth = self.nodes.iter().map(|n| n.depth).max().unwrap_or(0);
            self.stats.avg_depth = self.nodes.iter().map(|n| n.depth as f64).sum::<f64>() / self.nodes.len() as f64;
        }
        
        // Top packages by dependent count
        let mut by_dependents: Vec<_> = self.nodes.iter()
            .map(|n| (n.name.clone(), n.dependent_count))
            .collect();
        by_dependents.sort_by(|a, b| b.1.cmp(&a.1));
        self.stats.most_depended = by_dependents.into_iter().take(10).collect();
        
        // Top packages by dependency count
        let mut by_dependencies: Vec<_> = self.nodes.iter()
            .map(|n| (n.name.clone(), n.dependency_count))
            .collect();
        by_dependencies.sort_by(|a, b| b.1.cmp(&a.1));
        self.stats.most_dependencies = by_dependencies.into_iter().take(10).collect();
    }

    /// Detect issues in the dependency graph
    fn detect_issues(&mut self) {
        self.detect_circular_dependencies();
        self.detect_duplicate_packages();
        self.detect_deep_chains();
        self.detect_high_counts();
    }

    /// Detect circular dependencies using DFS
    fn detect_circular_dependencies(&mut self) {
        let adj: HashMap<&str, Vec<&str>> = self.edges.iter()
            .fold(HashMap::new(), |mut acc, edge| {
                acc.entry(&edge.from).or_default().push(&edge.to);
                acc
            });
        
        let mut visited: HashSet<&str> = HashSet::new();
        let mut rec_stack: HashSet<&str> = HashSet::new();
        let mut cycles: Vec<Vec<String>> = Vec::new();
        
        for node in &self.nodes {
            if !visited.contains(node.id.as_str()) {
                let mut path = Vec::new();
                self.find_cycles(&adj, &node.id, &mut visited, &mut rec_stack, &mut path, &mut cycles);
            }
        }
        
        for cycle in cycles {
            self.issues.push(DependencyIssue {
                issue_type: DependencyIssueType::CircularDependency,
                severity: Severity::High,
                components: cycle.clone(),
                description: format!("Circular dependency detected: {}", cycle.join(" -> ")),
                recommendation: "Review and refactor dependencies to break the cycle".to_string(),
            });
        }
    }

    /// Helper function to find cycles using DFS
    fn find_cycles<'a>(
        &self,
        adj: &HashMap<&str, Vec<&'a str>>,
        node: &'a str,
        visited: &mut HashSet<&'a str>,
        rec_stack: &mut HashSet<&'a str>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);
        path.push(node.to_string());
        
        if let Some(neighbors) = adj.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    self.find_cycles(adj, neighbor, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(neighbor) {
                    // Found a cycle
                    let cycle_start = path.iter().position(|n| n == *neighbor).unwrap_or(0);
                    let cycle: Vec<String> = path[cycle_start..].to_vec();
                    if !cycles.iter().any(|c| c == &cycle) {
                        cycles.push(cycle);
                    }
                }
            }
        }
        
        path.pop();
        rec_stack.remove(node);
    }

    /// Detect duplicate packages (same name, different versions)
    fn detect_duplicate_packages(&mut self) {
        let mut by_name: HashMap<&str, Vec<&DependencyNode>> = HashMap::new();
        
        for node in &self.nodes {
            by_name.entry(&node.name).or_default().push(node);
        }
        
        for (name, nodes) in by_name {
            if nodes.len() > 1 {
                let versions: Vec<String> = nodes.iter().map(|n| n.version.clone()).collect();
                
                self.issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::DuplicatePackage,
                    severity: Severity::Medium,
                    components: nodes.iter().map(|n| n.id.clone()).collect(),
                    description: format!("Multiple versions of '{}' detected: {}", name, versions.join(", ")),
                    recommendation: "Consider consolidating to a single version to reduce bundle size and potential conflicts".to_string(),
                });
            }
        }
    }

    /// Detect deep dependency chains
    fn detect_deep_chains(&mut self) {
        const DEPTH_THRESHOLD: u32 = 10;
        
        let deep_nodes: Vec<&DependencyNode> = self.nodes.iter()
            .filter(|n| n.depth >= DEPTH_THRESHOLD)
            .collect();
        
        if !deep_nodes.is_empty() {
            self.issues.push(DependencyIssue {
                issue_type: DependencyIssueType::DeepDependencyChain,
                severity: Severity::Low,
                components: deep_nodes.iter().map(|n| n.id.clone()).collect(),
                description: format!(
                    "{} packages are at depth {} or greater in the dependency tree",
                    deep_nodes.len(), DEPTH_THRESHOLD
                ),
                recommendation: "Deep dependency chains increase supply chain risk. Consider auditing these transitive dependencies.".to_string(),
            });
        }
    }

    /// Detect packages with unusually high counts
    fn detect_high_counts(&mut self) {
        const HIGH_DEPENDENCY_THRESHOLD: u32 = 50;
        const HIGH_DEPENDENT_THRESHOLD: u32 = 20;
        
        // High dependency count
        for node in &self.nodes {
            if node.dependency_count >= HIGH_DEPENDENCY_THRESHOLD {
                self.issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::HighDependencyCount,
                    severity: Severity::Low,
                    components: vec![node.id.clone()],
                    description: format!(
                        "'{}' has {} dependencies, which is unusually high",
                        node.name, node.dependency_count
                    ),
                    recommendation: "Consider if all these dependencies are necessary, or if a lighter alternative exists".to_string(),
                });
            }
            
            if node.dependent_count >= HIGH_DEPENDENT_THRESHOLD && !node.is_direct {
                self.issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::HighDependentCount,
                    severity: Severity::Medium,
                    components: vec![node.id.clone()],
                    description: format!(
                        "'{}' is a transitive dependency used by {} packages. Compromise could have wide impact.",
                        node.name, node.dependent_count
                    ),
                    recommendation: "Ensure this critical transitive dependency is well-maintained and regularly audited".to_string(),
                });
            }
        }
    }

    /// Get the dependency tree for a specific component
    pub fn get_dependency_tree(&self, component_id: &str) -> Vec<&DependencyNode> {
        let adj: HashMap<&str, Vec<&str>> = self.edges.iter()
            .fold(HashMap::new(), |mut acc, edge| {
                acc.entry(&edge.from).or_default().push(&edge.to);
                acc
            });
        
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        self.collect_dependencies(&adj, component_id, &mut visited, &mut result);
        result
    }

    fn collect_dependencies<'a>(
        &'a self,
        adj: &HashMap<&str, Vec<&str>>,
        node: &str,
        visited: &mut HashSet<String>,
        result: &mut Vec<&'a DependencyNode>,
    ) {
        if visited.contains(node) {
            return;
        }
        visited.insert(node.to_string());
        
        if let Some(dep_node) = self.nodes.iter().find(|n| n.id == node) {
            result.push(dep_node);
        }
        
        if let Some(neighbors) = adj.get(node) {
            for neighbor in neighbors {
                self.collect_dependencies(adj, neighbor, visited, result);
            }
        }
    }

    /// Export to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph dependencies {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box];\n");
        
        // Add nodes
        for node in &self.nodes {
            let color = if node.is_direct { "lightblue" } else { "white" };
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\\n{}\" style=filled fillcolor={}];\n",
                node.id, node.name, node.version, color
            ));
        }
        
        // Add edges
        for edge in &self.edges {
            dot.push_str(&format!("  \"{}\" -> \"{}\";\n", edge.from, edge.to));
        }
        
        dot.push_str("}\n");
        dot
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph() {
        let graph = DependencyGraph::new();
        assert_eq!(graph.stats.total_nodes, 0);
        assert_eq!(graph.stats.total_edges, 0);
    }

    #[test]
    fn test_graph_from_components() {
        let components = vec![
            SbomComponent {
                id: "comp-1".to_string(),
                project_id: "proj-1".to_string(),
                name: "package-a".to_string(),
                version: "1.0.0".to_string(),
                purl: None,
                cpe: None,
                license: None,
                license_risk: LicenseRisk::Low,
                is_direct: true,
                parent_id: None,
                vulnerabilities: Vec::new(),
                created_at: chrono::Utc::now(),
            },
            SbomComponent {
                id: "comp-2".to_string(),
                project_id: "proj-1".to_string(),
                name: "package-b".to_string(),
                version: "2.0.0".to_string(),
                purl: None,
                cpe: None,
                license: None,
                license_risk: LicenseRisk::Low,
                is_direct: false,
                parent_id: Some("comp-1".to_string()),
                vulnerabilities: Vec::new(),
                created_at: chrono::Utc::now(),
            },
        ];
        
        let mut deps = HashMap::new();
        deps.insert("comp-1".to_string(), vec!["comp-2".to_string()]);
        
        let graph = DependencyGraph::from_components(&components, &deps);
        
        assert_eq!(graph.stats.total_nodes, 2);
        assert_eq!(graph.stats.total_edges, 1);
        assert_eq!(graph.stats.direct_dependencies, 1);
        assert_eq!(graph.stats.transitive_dependencies, 1);
    }

    #[test]
    fn test_dot_export() {
        let graph = DependencyGraph::new();
        let dot = graph.to_dot();
        assert!(dot.contains("digraph dependencies"));
        assert!(dot.contains("rankdir=LR"));
    }
}
