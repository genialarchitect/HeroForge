//! Attack Path Analysis Module
//!
//! This module provides attack path analysis capabilities by building graphs
//! from scan results and identifying potential attack chains.

pub mod analyzer;
pub mod graph;
pub mod scoring;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use analyzer::AttackPathAnalyzer;
pub use graph::{AttackNode, AttackEdge};
pub use scoring::AttackPathScorer;

use crate::types::HostInfo;

/// Risk level for attack paths
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            "critical" => Some(RiskLevel::Critical),
            _ => None,
        }
    }

    pub fn from_cvss(score: f64) -> Self {
        if score >= 9.0 {
            RiskLevel::Critical
        } else if score >= 7.0 {
            RiskLevel::High
        } else if score >= 4.0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a complete attack path through the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub name: Option<String>,
    pub risk_level: RiskLevel,
    pub probability: f64,
    pub total_cvss: f64,
    pub path_length: usize,
    pub description: Option<String>,
    pub mitigation_steps: Vec<String>,
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
}

impl AttackPath {
    /// Create a new attack path
    pub fn new(nodes: Vec<AttackNode>, edges: Vec<AttackEdge>) -> Self {
        let path_length = nodes.len();
        let total_cvss: f64 = nodes.iter()
            .flat_map(|n| &n.vulnerability_ids)
            .count() as f64 * 5.0; // Simplified CVSS estimation

        let risk_level = RiskLevel::from_cvss(total_cvss / path_length.max(1) as f64);
        let probability = edges.iter()
            .map(|e| e.likelihood)
            .product::<f64>();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: None,
            risk_level,
            probability,
            total_cvss,
            path_length,
            description: None,
            mitigation_steps: Vec::new(),
            nodes,
            edges,
        }
    }
}

/// Result of attack path analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathAnalysisResult {
    pub scan_id: String,
    pub paths: Vec<AttackPath>,
    pub critical_paths: Vec<AttackPath>,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub highest_risk: RiskLevel,
    pub analysis_timestamp: chrono::DateTime<chrono::Utc>,
}

/// Analyze scan results for attack paths
pub async fn analyze_scan_for_attack_paths(
    scan_id: &str,
    hosts: &[HostInfo],
) -> Result<AttackPathAnalysisResult> {
    let analyzer = AttackPathAnalyzer::new();
    let graph = analyzer.build_graph(hosts);
    let paths = analyzer.find_attack_paths(&graph);

    let scorer = AttackPathScorer::new();
    let mut scored_paths: Vec<AttackPath> = paths
        .into_iter()
        .map(|p| {
            let score = scorer.score_path(&p.nodes, &p.edges);
            AttackPath {
                risk_level: RiskLevel::from_cvss(score.total_risk_score),
                probability: score.exploitation_probability,
                total_cvss: score.cumulative_cvss,
                mitigation_steps: score.recommended_mitigations,
                ..p
            }
        })
        .collect();

    // Sort by risk level and probability
    scored_paths.sort_by(|a, b| {
        b.risk_level.cmp(&a.risk_level)
            .then(b.probability.partial_cmp(&a.probability).unwrap_or(std::cmp::Ordering::Equal))
    });

    let critical_paths: Vec<AttackPath> = scored_paths
        .iter()
        .filter(|p| p.risk_level == RiskLevel::Critical || p.risk_level == RiskLevel::High)
        .cloned()
        .collect();

    let highest_risk = scored_paths
        .first()
        .map(|p| p.risk_level.clone())
        .unwrap_or(RiskLevel::Low);

    Ok(AttackPathAnalysisResult {
        scan_id: scan_id.to_string(),
        paths: scored_paths,
        critical_paths,
        total_nodes: graph.nodes.len(),
        total_edges: graph.edges.len(),
        highest_risk,
        analysis_timestamp: chrono::Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_cvss() {
        assert_eq!(RiskLevel::from_cvss(9.5), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_cvss(8.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_cvss(5.5), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_cvss(2.0), RiskLevel::Low);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
    }
}
