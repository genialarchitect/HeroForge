//! Attack Path Scoring
//!
//! Calculates risk scores for attack paths based on vulnerability chains,
//! exploitability, and impact.

use super::graph::{AttackEdge, AttackNode, NodeType};
use super::RiskLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Weights for different scoring factors
#[derive(Debug, Clone)]
pub struct ScoringWeights {
    pub vulnerability_weight: f64,
    pub exploitability_weight: f64,
    pub impact_weight: f64,
    pub path_length_weight: f64,
    pub target_criticality_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            vulnerability_weight: 0.35,
            exploitability_weight: 0.25,
            impact_weight: 0.25,
            path_length_weight: 0.05,
            target_criticality_weight: 0.10,
        }
    }
}

/// Score for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathScore {
    /// Overall risk score (0-10)
    pub total_risk_score: f64,
    /// Cumulative CVSS-like score
    pub cumulative_cvss: f64,
    /// Probability of successful exploitation (0-1)
    pub exploitation_probability: f64,
    /// Impact if attack succeeds (0-10)
    pub potential_impact: f64,
    /// Path complexity factor (lower = easier to exploit)
    pub complexity_factor: f64,
    /// Risk level classification
    pub risk_level: RiskLevel,
    /// Recommended mitigations
    pub recommended_mitigations: Vec<String>,
    /// Component scores breakdown
    pub score_breakdown: HashMap<String, f64>,
}

/// Attack path scorer
#[derive(Debug, Clone)]
pub struct AttackPathScorer {
    weights: ScoringWeights,
    /// CVSS base scores for common vulnerability types
    cvss_base_scores: HashMap<String, f64>,
    /// Criticality scores for target services
    target_criticality: HashMap<String, f64>,
}

impl Default for AttackPathScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackPathScorer {
    /// Create a new scorer with default weights
    pub fn new() -> Self {
        let mut scorer = Self {
            weights: ScoringWeights::default(),
            cvss_base_scores: HashMap::new(),
            target_criticality: HashMap::new(),
        };
        scorer.initialize_cvss_scores();
        scorer.initialize_criticality_scores();
        scorer
    }

    /// Create a scorer with custom weights
    pub fn with_weights(weights: ScoringWeights) -> Self {
        let mut scorer = Self {
            weights,
            cvss_base_scores: HashMap::new(),
            target_criticality: HashMap::new(),
        };
        scorer.initialize_cvss_scores();
        scorer.initialize_criticality_scores();
        scorer
    }

    fn initialize_cvss_scores(&mut self) {
        // Common vulnerability type base scores
        self.cvss_base_scores.insert("rce".to_string(), 9.8);
        self.cvss_base_scores.insert("sqli".to_string(), 9.1);
        self.cvss_base_scores.insert("auth_bypass".to_string(), 8.8);
        self.cvss_base_scores.insert("privilege_escalation".to_string(), 8.5);
        self.cvss_base_scores.insert("info_disclosure".to_string(), 6.5);
        self.cvss_base_scores.insert("dos".to_string(), 5.5);
        self.cvss_base_scores.insert("xss".to_string(), 6.1);
        self.cvss_base_scores.insert("csrf".to_string(), 5.4);
        self.cvss_base_scores.insert("ssrf".to_string(), 7.5);
        self.cvss_base_scores.insert("lfi".to_string(), 7.8);
        self.cvss_base_scores.insert("rfi".to_string(), 8.5);
        self.cvss_base_scores.insert("default".to_string(), 5.0);
    }

    fn initialize_criticality_scores(&mut self) {
        // Target service criticality (0-10)
        self.target_criticality.insert("mysql".to_string(), 9.0);
        self.target_criticality.insert("postgresql".to_string(), 9.0);
        self.target_criticality.insert("mongodb".to_string(), 9.0);
        self.target_criticality.insert("mssql".to_string(), 9.0);
        self.target_criticality.insert("oracle".to_string(), 9.5);
        self.target_criticality.insert("redis".to_string(), 7.0);
        self.target_criticality.insert("elasticsearch".to_string(), 8.0);
        self.target_criticality.insert("ldap".to_string(), 8.5);
        self.target_criticality.insert("kerberos".to_string(), 9.0);
        self.target_criticality.insert("domain".to_string(), 9.5);
        self.target_criticality.insert("smb".to_string(), 7.5);
        self.target_criticality.insert("ssh".to_string(), 6.0);
        self.target_criticality.insert("rdp".to_string(), 7.0);
        self.target_criticality.insert("http".to_string(), 5.0);
        self.target_criticality.insert("https".to_string(), 5.0);
        self.target_criticality.insert("default".to_string(), 4.0);
    }

    /// Score an attack path
    pub fn score_path(&self, nodes: &[AttackNode], edges: &[AttackEdge]) -> PathScore {
        let mut score_breakdown = HashMap::new();

        // Calculate vulnerability score
        let vuln_score = self.calculate_vulnerability_score(nodes);
        score_breakdown.insert("vulnerability".to_string(), vuln_score);

        // Calculate exploitability score based on edges
        let exploitability_score = self.calculate_exploitability_score(edges);
        score_breakdown.insert("exploitability".to_string(), exploitability_score);

        // Calculate impact score based on target nodes
        let impact_score = self.calculate_impact_score(nodes);
        score_breakdown.insert("impact".to_string(), impact_score);

        // Calculate path complexity
        let complexity_score = self.calculate_complexity_score(nodes, edges);
        score_breakdown.insert("complexity".to_string(), complexity_score);

        // Calculate target criticality
        let criticality_score = self.calculate_criticality_score(nodes);
        score_breakdown.insert("criticality".to_string(), criticality_score);

        // Calculate weighted total score
        let total_risk_score = (vuln_score * self.weights.vulnerability_weight
            + exploitability_score * self.weights.exploitability_weight
            + impact_score * self.weights.impact_weight
            + (10.0 - complexity_score) * self.weights.path_length_weight
            + criticality_score * self.weights.target_criticality_weight)
            .min(10.0);

        // Calculate cumulative CVSS
        let cumulative_cvss = self.calculate_cumulative_cvss(nodes, edges);

        // Calculate exploitation probability
        let exploitation_probability = self.calculate_exploitation_probability(nodes, edges);

        // Generate mitigations
        let recommended_mitigations = self.generate_mitigations(nodes, edges);

        PathScore {
            total_risk_score,
            cumulative_cvss,
            exploitation_probability,
            potential_impact: impact_score,
            complexity_factor: complexity_score,
            risk_level: RiskLevel::from_cvss(total_risk_score),
            recommended_mitigations,
            score_breakdown,
        }
    }

    /// Calculate vulnerability score based on nodes
    fn calculate_vulnerability_score(&self, nodes: &[AttackNode]) -> f64 {
        let total_vulns: usize = nodes.iter().map(|n| n.vulnerability_count()).sum();
        let vulnerable_nodes = nodes.iter().filter(|n| n.has_vulnerabilities()).count();

        if total_vulns == 0 {
            return 3.0; // Base score for path without known vulnerabilities
        }

        // Higher score for more vulnerabilities and more affected nodes
        let base_score = (total_vulns as f64 * 1.5).min(8.0);
        let coverage_bonus = (vulnerable_nodes as f64 / nodes.len() as f64) * 2.0;

        (base_score + coverage_bonus).min(10.0)
    }

    /// Calculate exploitability score based on edges
    fn calculate_exploitability_score(&self, edges: &[AttackEdge]) -> f64 {
        if edges.is_empty() {
            return 5.0;
        }

        let avg_likelihood: f64 =
            edges.iter().map(|e| e.likelihood).sum::<f64>() / edges.len() as f64;

        // Scale to 0-10
        avg_likelihood * 10.0
    }

    /// Calculate impact score based on target nodes
    fn calculate_impact_score(&self, nodes: &[AttackNode]) -> f64 {
        let target_nodes: Vec<&AttackNode> = nodes
            .iter()
            .filter(|n| n.node_type == NodeType::Target)
            .collect();

        if target_nodes.is_empty() {
            return 5.0;
        }

        let mut max_impact = 0.0f64;
        for node in target_nodes {
            if let Some(service) = &node.service {
                let criticality = self
                    .target_criticality
                    .get(&service.to_lowercase())
                    .copied()
                    .unwrap_or(*self.target_criticality.get("default").unwrap_or(&4.0));
                max_impact = max_impact.max(criticality);
            }
        }

        max_impact
    }

    /// Calculate complexity score (lower = more dangerous)
    fn calculate_complexity_score(&self, nodes: &[AttackNode], edges: &[AttackEdge]) -> f64 {
        // Shorter paths are easier to exploit
        let path_length_factor = (nodes.len() as f64 / 2.0).min(5.0);

        // Paths with high likelihood edges are easier
        let avg_likelihood = if edges.is_empty() {
            0.5
        } else {
            edges.iter().map(|e| e.likelihood).sum::<f64>() / edges.len() as f64
        };

        let ease_factor = avg_likelihood * 5.0;

        path_length_factor + (5.0 - ease_factor)
    }

    /// Calculate target criticality score
    fn calculate_criticality_score(&self, nodes: &[AttackNode]) -> f64 {
        let mut max_criticality = 0.0f64;

        for node in nodes {
            if let Some(service) = &node.service {
                let criticality = self
                    .target_criticality
                    .get(&service.to_lowercase())
                    .copied()
                    .unwrap_or(*self.target_criticality.get("default").unwrap_or(&4.0));

                // Increase criticality for nodes with vulnerabilities
                let vuln_multiplier = if node.has_vulnerabilities() { 1.2 } else { 1.0 };

                max_criticality = max_criticality.max(criticality * vuln_multiplier);
            }
        }

        max_criticality.min(10.0)
    }

    /// Calculate cumulative CVSS score
    fn calculate_cumulative_cvss(&self, nodes: &[AttackNode], edges: &[AttackEdge]) -> f64 {
        let mut total_cvss = 0.0;

        // Add base score for each vulnerability
        for node in nodes {
            total_cvss += node.vulnerability_count() as f64
                * *self.cvss_base_scores.get("default").unwrap_or(&5.0);
        }

        // Add impact from edges
        for edge in edges {
            total_cvss += edge.impact * edge.likelihood;
        }

        total_cvss
    }

    /// Calculate exploitation probability
    fn calculate_exploitation_probability(&self, nodes: &[AttackNode], edges: &[AttackEdge]) -> f64 {
        if edges.is_empty() {
            return if nodes.iter().any(|n| n.has_vulnerabilities()) {
                0.3
            } else {
                0.1
            };
        }

        // Chain probability = product of individual probabilities
        let mut probability: f64 = 1.0;
        for edge in edges {
            probability *= edge.likelihood;
        }

        // Increase probability if vulnerabilities exist
        if nodes.iter().any(|n| n.has_vulnerabilities()) {
            probability = (probability * 1.3).min(1.0);
        }

        probability
    }

    /// Generate recommended mitigations
    fn generate_mitigations(&self, nodes: &[AttackNode], edges: &[AttackEdge]) -> Vec<String> {
        let mut mitigations = Vec::new();

        // Analyze entry points
        for node in nodes.iter().filter(|n| n.node_type == NodeType::Entry) {
            if let Some(service) = &node.service {
                match service.to_lowercase().as_str() {
                    "ssh" => {
                        mitigations.push("Implement SSH key-based authentication".to_string());
                        mitigations.push("Disable root SSH login".to_string());
                        mitigations.push("Use SSH jump hosts for internal access".to_string());
                    }
                    "rdp" => {
                        mitigations.push("Enable Network Level Authentication (NLA) for RDP".to_string());
                        mitigations.push("Implement RDP Gateway for secure access".to_string());
                        mitigations.push("Use multi-factor authentication for RDP".to_string());
                    }
                    "http" | "https" => {
                        mitigations.push("Implement Web Application Firewall (WAF)".to_string());
                        mitigations.push("Enable input validation and output encoding".to_string());
                        mitigations.push("Use Content Security Policy headers".to_string());
                    }
                    "ftp" => {
                        mitigations.push("Replace FTP with SFTP or FTPS".to_string());
                        mitigations.push("Restrict FTP access to specific IP ranges".to_string());
                    }
                    "telnet" => {
                        mitigations.push("Disable Telnet and use SSH instead".to_string());
                    }
                    _ => {}
                }
            }

            if node.has_vulnerabilities() {
                mitigations.push(format!(
                    "Patch {} vulnerabilities on {} ({})",
                    node.vulnerability_count(),
                    node.host_ip.as_deref().unwrap_or("unknown"),
                    node.service.as_deref().unwrap_or("unknown")
                ));
            }
        }

        // Analyze target nodes
        for node in nodes.iter().filter(|n| n.node_type == NodeType::Target) {
            if let Some(service) = &node.service {
                match service.to_lowercase().as_str() {
                    "mysql" | "postgresql" | "mongodb" | "mssql" | "oracle" => {
                        mitigations.push("Implement database access controls".to_string());
                        mitigations.push("Encrypt database connections with TLS".to_string());
                        mitigations.push("Use least-privilege database accounts".to_string());
                        mitigations.push("Enable database audit logging".to_string());
                    }
                    "ldap" => {
                        mitigations.push("Enable LDAP Signing and Sealing".to_string());
                        mitigations.push("Implement LDAPS (LDAP over SSL)".to_string());
                    }
                    "smb" => {
                        mitigations.push("Disable SMBv1 protocol".to_string());
                        mitigations.push("Enable SMB signing".to_string());
                        mitigations.push("Implement proper share permissions".to_string());
                    }
                    _ => {}
                }
            }
        }

        // Analyze edges for technique-specific mitigations
        for edge in edges {
            if let Some(technique_id) = &edge.technique_id {
                match technique_id.as_str() {
                    "T1021" | "T1021.001" | "T1021.002" | "T1021.004" => {
                        if !mitigations.iter().any(|m| m.contains("segmentation")) {
                            mitigations.push("Implement network segmentation".to_string());
                        }
                    }
                    "T1213" => {
                        if !mitigations.iter().any(|m| m.contains("least-privilege")) {
                            mitigations.push("Implement least-privilege access controls".to_string());
                        }
                    }
                    "T1190" => {
                        if !mitigations.iter().any(|m| m.contains("WAF")) {
                            mitigations.push("Deploy Web Application Firewall (WAF)".to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // General mitigations based on path characteristics
        if nodes.len() > 3 {
            mitigations.push("Implement micro-segmentation to limit lateral movement".to_string());
        }

        if edges.iter().any(|e| e.likelihood > 0.7) {
            mitigations.push("Deploy endpoint detection and response (EDR) solutions".to_string());
        }

        // Deduplicate and return
        mitigations.sort();
        mitigations.dedup();
        mitigations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoring_weights_default() {
        let weights = ScoringWeights::default();
        let total: f64 = weights.vulnerability_weight
            + weights.exploitability_weight
            + weights.impact_weight
            + weights.path_length_weight
            + weights.target_criticality_weight;

        assert!((total - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_score_empty_path() {
        let scorer = AttackPathScorer::new();
        let score = scorer.score_path(&[], &[]);

        assert!(score.total_risk_score >= 0.0);
        assert!(score.total_risk_score <= 10.0);
    }

    #[test]
    fn test_score_path_with_vulnerabilities() {
        let scorer = AttackPathScorer::new();

        let mut entry_node = AttackNode::new(
            Some("192.168.1.1".to_string()),
            Some(22),
            Some("ssh".to_string()),
            NodeType::Entry,
        );
        entry_node.add_vulnerability("CVE-2021-1234".to_string());

        let target_node = AttackNode::new(
            Some("192.168.1.2".to_string()),
            Some(3306),
            Some("mysql".to_string()),
            NodeType::Target,
        );

        let edge = AttackEdge::new(
            entry_node.id.clone(),
            target_node.id.clone(),
            Some("SSH to MySQL".to_string()),
            Some("T1021".to_string()),
        )
        .with_likelihood(0.7)
        .with_impact(8.0);

        let score = scorer.score_path(&[entry_node, target_node], &[edge]);

        assert!(score.total_risk_score > 5.0);
        assert!(!score.recommended_mitigations.is_empty());
    }

    #[test]
    fn test_exploitation_probability() {
        let scorer = AttackPathScorer::new();

        let edge1 = AttackEdge::new(
            "a".to_string(),
            "b".to_string(),
            None,
            None,
        )
        .with_likelihood(0.8);

        let edge2 = AttackEdge::new(
            "b".to_string(),
            "c".to_string(),
            None,
            None,
        )
        .with_likelihood(0.6);

        let node1 = AttackNode::new(None, None, None, NodeType::Entry);
        let node2 = AttackNode::new(None, None, None, NodeType::Pivot);
        let node3 = AttackNode::new(None, None, None, NodeType::Target);

        let score = scorer.score_path(&[node1, node2, node3], &[edge1, edge2]);

        // Probability should be roughly 0.8 * 0.6 = 0.48
        assert!(score.exploitation_probability > 0.4 && score.exploitation_probability < 0.6);
    }
}
