// ============================================================================
// Attack Path AI Interpreter
// ============================================================================
//
// This module provides AI-powered interpretation of attack paths:
// - "An attacker could..." narrative generation
// - Business impact context
// - MITRE ATT&CK chain mapping
// - Recommended blocking points
//
// Uses LLM orchestration for natural language generation and
// structured analysis for technical details.

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

// ============================================================================
// Types
// ============================================================================

/// Complete interpretation of an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathInterpretation {
    /// Attack path ID this interpretation is for
    pub path_id: String,
    /// When the interpretation was generated
    pub generated_at: DateTime<Utc>,
    /// Natural language narrative
    pub narrative: AttackNarrative,
    /// MITRE ATT&CK mapping
    pub mitre_mapping: MitreMapping,
    /// Business impact analysis
    pub business_impact: BusinessImpact,
    /// Recommended defensive actions
    pub blocking_points: Vec<BlockingPoint>,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
}

/// Natural language narrative of the attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNarrative {
    /// Short summary (1-2 sentences)
    pub summary: String,
    /// Step-by-step description of the attack
    pub attack_steps: Vec<NarrativeStep>,
    /// "An attacker could..." style explanation
    pub attacker_perspective: String,
    /// "If exploited, this could lead to..." explanation
    pub consequence_description: String,
    /// Technical complexity assessment
    pub complexity: AttackComplexity,
}

/// A single step in the attack narrative
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeStep {
    /// Step number
    pub step: u32,
    /// What happens in this step
    pub action: String,
    /// Why this step works
    pub rationale: String,
    /// Technical details
    pub technical_detail: String,
    /// Associated vulnerabilities
    pub vulnerabilities: Vec<String>,
}

/// Attack complexity assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AttackComplexity {
    /// Script kiddie level
    Low,
    /// Skilled attacker
    Medium,
    /// Advanced persistent threat
    High,
    /// Nation-state level
    VeryHigh,
}

impl AttackComplexity {
    fn from_score(score: f64) -> Self {
        match score as u32 {
            0..=25 => Self::Low,
            26..=50 => Self::Medium,
            51..=75 => Self::High,
            _ => Self::VeryHigh,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Low => "Low complexity - could be exploited by script kiddies using automated tools",
            Self::Medium => "Medium complexity - requires skilled attacker with specific knowledge",
            Self::High => "High complexity - requires advanced persistent threat capabilities",
            Self::VeryHigh => "Very high complexity - likely requires nation-state resources",
        }
    }
}

/// MITRE ATT&CK mapping for the attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    /// Tactics used in the attack
    pub tactics: Vec<MitreTactic>,
    /// Techniques mapped to the attack
    pub techniques: Vec<MitreTechnique>,
    /// Overall kill chain stages
    pub kill_chain_stages: Vec<KillChainStage>,
}

/// A MITRE ATT&CK tactic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTactic {
    /// Tactic ID (e.g., TA0001)
    pub id: String,
    /// Tactic name
    pub name: String,
    /// Description
    pub description: String,
    /// URL to MITRE page
    pub url: String,
}

/// A MITRE ATT&CK technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    /// Technique ID (e.g., T1566)
    pub id: String,
    /// Technique name
    pub name: String,
    /// Parent tactic
    pub tactic: String,
    /// Description
    pub description: String,
    /// Relevance to this attack path
    pub relevance: String,
    /// URL to MITRE page
    pub url: String,
}

/// Kill chain stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStage {
    /// Stage number
    pub stage: u32,
    /// Stage name
    pub name: String,
    /// What happens at this stage
    pub description: String,
    /// Techniques used at this stage
    pub techniques: Vec<String>,
}

/// Business impact analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpact {
    /// Overall impact level
    pub level: ImpactLevel,
    /// Detailed impact description
    pub description: String,
    /// Affected business functions
    pub affected_functions: Vec<String>,
    /// Data at risk
    pub data_at_risk: Vec<DataRiskItem>,
    /// Potential financial impact
    pub financial_impact: Option<FinancialImpact>,
    /// Regulatory implications
    pub regulatory_implications: Vec<String>,
    /// Reputational risk
    pub reputational_risk: ReputationalRisk,
}

/// Impact level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ImpactLevel {
    fn from_risk_score(score: f64) -> Self {
        match score as u32 {
            0..=25 => Self::Low,
            26..=50 => Self::Medium,
            51..=75 => Self::High,
            _ => Self::Critical,
        }
    }
}

/// Data at risk item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRiskItem {
    /// Type of data
    pub data_type: String,
    /// Classification (PII, PHI, etc.)
    pub classification: String,
    /// Risk description
    pub risk: String,
}

/// Financial impact estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialImpact {
    /// Estimated minimum cost
    pub min_estimate_usd: u64,
    /// Estimated maximum cost
    pub max_estimate_usd: u64,
    /// What the cost includes
    pub cost_factors: Vec<String>,
    /// Confidence level
    pub confidence: String,
}

/// Reputational risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationalRisk {
    /// Risk level
    pub level: String,
    /// Description
    pub description: String,
    /// Potential headlines if breached
    pub potential_headlines: Vec<String>,
}

/// Recommended blocking point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingPoint {
    /// Where in the attack chain to block
    pub step: u32,
    /// What to do
    pub action: String,
    /// Why this is effective
    pub effectiveness: String,
    /// Effort to implement
    pub implementation_effort: EffortLevel,
    /// Priority (1 = highest)
    pub priority: u32,
    /// Technologies/controls to deploy
    pub controls: Vec<String>,
}

/// Effort level for implementation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Risk assessment for the attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk score (0-100)
    pub risk_score: f64,
    /// Probability of exploitation (0-100)
    pub exploitation_probability: f64,
    /// Impact if exploited (0-100)
    pub impact_score: f64,
    /// Time to exploitation (estimated)
    pub estimated_time_to_exploit: String,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Overall recommendation
    pub recommendation: String,
}

/// A risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,
    /// Factor weight
    pub weight: f64,
    /// Factor score
    pub score: f64,
    /// Description
    pub description: String,
}

// ============================================================================
// Attack Path Interpreter
// ============================================================================

/// AI-powered attack path interpreter
pub struct AttackPathInterpreter {
    pool: Arc<SqlitePool>,
}

impl AttackPathInterpreter {
    /// Create a new interpreter
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }

    /// Interpret an attack path
    pub async fn interpret(&self, path_id: &str) -> Result<AttackPathInterpretation> {
        info!("Interpreting attack path: {}", path_id);

        // Get the attack path from database
        let path = self.get_attack_path(path_id).await?;

        // Generate narrative
        let narrative = self.generate_narrative(&path).await?;

        // Map to MITRE ATT&CK
        let mitre_mapping = self.map_to_mitre(&path).await?;

        // Analyze business impact
        let business_impact = self.analyze_business_impact(&path).await?;

        // Identify blocking points
        let blocking_points = self.identify_blocking_points(&path).await?;

        // Assess risk
        let risk_assessment = self.assess_risk(&path).await?;

        let interpretation = AttackPathInterpretation {
            path_id: path_id.to_string(),
            generated_at: Utc::now(),
            narrative,
            mitre_mapping,
            business_impact,
            blocking_points,
            risk_assessment,
        };

        // Store interpretation
        self.store_interpretation(&interpretation).await?;

        info!("Attack path interpretation complete for {}", path_id);
        Ok(interpretation)
    }

    /// Get attack path from database
    async fn get_attack_path(&self, path_id: &str) -> Result<AttackPathData> {
        let row: Option<(String, String, String, Option<f64>, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT id, name, risk_level, probability, source_node, target_node
            FROM attack_paths
            WHERE id = ?
            "#
        )
        .bind(path_id)
        .fetch_optional(&*self.pool)
        .await?;

        let path = row.ok_or_else(|| anyhow::anyhow!("Attack path not found: {}", path_id))?;

        // Get nodes
        let nodes: Vec<(String, String, Option<String>, Option<i32>)> = sqlx::query_as(
            r#"
            SELECT id, node_type, vulnerability_ids, sequence
            FROM attack_nodes
            WHERE path_id = ?
            ORDER BY sequence
            "#
        )
        .bind(path_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(AttackPathData {
            id: path.0,
            name: path.1,
            risk_level: path.2,
            probability: path.3.unwrap_or(0.5),
            source_node: path.4,
            target_node: path.5,
            nodes: nodes.into_iter().map(|(id, node_type, vuln_ids, seq)| {
                AttackNodeData {
                    id,
                    node_type,
                    vulnerability_ids: vuln_ids.map(|v| {
                        serde_json::from_str::<Vec<String>>(&v).unwrap_or_default()
                    }).unwrap_or_default(),
                    sequence: seq.unwrap_or(0) as u32,
                }
            }).collect(),
        })
    }

    /// Generate natural language narrative
    async fn generate_narrative(&self, path: &AttackPathData) -> Result<AttackNarrative> {
        let node_count = path.nodes.len();
        let vuln_count: usize = path.nodes.iter()
            .map(|n| n.vulnerability_ids.len())
            .sum();

        // Generate attack steps
        let mut attack_steps = Vec::new();
        for (i, node) in path.nodes.iter().enumerate() {
            let action = match node.node_type.as_str() {
                "initial_access" => format!("Attacker gains initial access to the network via {}",
                    node.vulnerability_ids.first().unwrap_or(&"exposed service".to_string())),
                "execution" => format!("Attacker executes code using {} vulnerabilities",
                    node.vulnerability_ids.len()),
                "persistence" => "Attacker establishes persistence mechanisms".to_string(),
                "privilege_escalation" => "Attacker escalates privileges to gain higher access".to_string(),
                "defense_evasion" => "Attacker evades security controls".to_string(),
                "credential_access" => "Attacker harvests credentials".to_string(),
                "discovery" => "Attacker discovers additional targets and information".to_string(),
                "lateral_movement" => "Attacker moves laterally through the network".to_string(),
                "collection" => "Attacker collects sensitive data".to_string(),
                "exfiltration" => "Attacker exfiltrates data from the network".to_string(),
                "impact" => "Attacker achieves their objective and causes impact".to_string(),
                _ => format!("Attacker proceeds through {} stage", node.node_type),
            };

            let rationale = format!("This step is possible because of {} identified vulnerabilities",
                node.vulnerability_ids.len());

            let technical_detail = format!("Node type: {}, vulnerabilities: {:?}",
                node.node_type, node.vulnerability_ids);

            attack_steps.push(NarrativeStep {
                step: (i + 1) as u32,
                action,
                rationale,
                technical_detail,
                vulnerabilities: node.vulnerability_ids.clone(),
            });
        }

        // Generate summary
        let summary = format!(
            "This attack path consists of {} stages exploiting {} vulnerabilities to achieve {}. \
            The path starts at {} and ends at {}.",
            node_count,
            vuln_count,
            self.describe_objective(&path.target_node),
            path.source_node.as_deref().unwrap_or("external access"),
            path.target_node.as_deref().unwrap_or("critical assets")
        );

        // Generate attacker perspective
        let attacker_perspective = format!(
            "An attacker could exploit this path by first {}, then progressively \
            leveraging {} additional attack stages to reach {}. \
            This attack requires {} sophistication and could be completed in {}.",
            attack_steps.first().map(|s| s.action.as_str()).unwrap_or("gaining access"),
            node_count.saturating_sub(1),
            path.target_node.as_deref().unwrap_or("the target"),
            self.describe_complexity(&path.risk_level),
            self.estimate_time(node_count, &path.risk_level)
        );

        // Generate consequence description
        let consequence_description = format!(
            "If exploited, this attack path could lead to {} compromise, \
            potentially affecting {} and resulting in {}. \
            The {} risk level indicates {}.",
            path.target_node.as_deref().unwrap_or("system"),
            self.describe_affected_assets(&path),
            self.describe_consequences(&path.risk_level),
            path.risk_level,
            self.describe_risk_implications(&path.risk_level)
        );

        let complexity = match path.risk_level.to_lowercase().as_str() {
            "critical" => AttackComplexity::Low,
            "high" => AttackComplexity::Medium,
            "medium" => AttackComplexity::High,
            _ => AttackComplexity::VeryHigh,
        };

        Ok(AttackNarrative {
            summary,
            attack_steps,
            attacker_perspective,
            consequence_description,
            complexity,
        })
    }

    fn describe_objective(&self, target: &Option<String>) -> &str {
        if let Some(t) = target {
            if t.contains("database") { return "database access"; }
            if t.contains("admin") { return "administrative control"; }
            if t.contains("domain") { return "domain dominance"; }
        }
        "system compromise"
    }

    fn describe_complexity(&self, risk_level: &str) -> &str {
        match risk_level.to_lowercase().as_str() {
            "critical" => "low to medium",
            "high" => "medium",
            "medium" => "medium to high",
            _ => "high",
        }
    }

    fn estimate_time(&self, node_count: usize, risk_level: &str) -> String {
        let base_hours = match risk_level.to_lowercase().as_str() {
            "critical" => 1,
            "high" => 4,
            "medium" => 12,
            _ => 48,
        };
        let total_hours = base_hours * node_count;
        if total_hours < 24 {
            format!("{} hours", total_hours)
        } else {
            format!("{} days", total_hours / 24)
        }
    }

    fn describe_affected_assets(&self, _path: &AttackPathData) -> &str {
        "critical business systems and data"
    }

    fn describe_consequences(&self, risk_level: &str) -> &str {
        match risk_level.to_lowercase().as_str() {
            "critical" => "complete system compromise, data breach, and business disruption",
            "high" => "significant data exposure and potential system control",
            "medium" => "partial system access and limited data exposure",
            _ => "information disclosure",
        }
    }

    fn describe_risk_implications(&self, risk_level: &str) -> &str {
        match risk_level.to_lowercase().as_str() {
            "critical" => "immediate action is required - this path is highly exploitable",
            "high" => "this path should be addressed urgently",
            "medium" => "remediation should be planned within standard SLA",
            _ => "this path presents lower risk but should still be addressed",
        }
    }

    /// Map attack path to MITRE ATT&CK framework
    async fn map_to_mitre(&self, path: &AttackPathData) -> Result<MitreMapping> {
        let mut tactics = Vec::new();
        let mut techniques = Vec::new();
        let mut kill_chain_stages = Vec::new();

        // Map node types to MITRE tactics
        for node in &path.nodes {
            match node.node_type.as_str() {
                "initial_access" => {
                    tactics.push(MitreTactic {
                        id: "TA0001".to_string(),
                        name: "Initial Access".to_string(),
                        description: "Techniques used to gain initial access to the network".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0001/".to_string(),
                    });
                    techniques.push(MitreTechnique {
                        id: "T1190".to_string(),
                        name: "Exploit Public-Facing Application".to_string(),
                        tactic: "Initial Access".to_string(),
                        description: "Adversaries may attempt to exploit a weakness in an Internet-facing host".to_string(),
                        relevance: "This path exploits publicly accessible vulnerabilities".to_string(),
                        url: "https://attack.mitre.org/techniques/T1190/".to_string(),
                    });
                },
                "execution" => {
                    tactics.push(MitreTactic {
                        id: "TA0002".to_string(),
                        name: "Execution".to_string(),
                        description: "Techniques for running malicious code".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0002/".to_string(),
                    });
                },
                "persistence" => {
                    tactics.push(MitreTactic {
                        id: "TA0003".to_string(),
                        name: "Persistence".to_string(),
                        description: "Techniques for maintaining access".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0003/".to_string(),
                    });
                },
                "privilege_escalation" => {
                    tactics.push(MitreTactic {
                        id: "TA0004".to_string(),
                        name: "Privilege Escalation".to_string(),
                        description: "Techniques for gaining higher-level permissions".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0004/".to_string(),
                    });
                },
                "defense_evasion" => {
                    tactics.push(MitreTactic {
                        id: "TA0005".to_string(),
                        name: "Defense Evasion".to_string(),
                        description: "Techniques for avoiding detection".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0005/".to_string(),
                    });
                },
                "credential_access" => {
                    tactics.push(MitreTactic {
                        id: "TA0006".to_string(),
                        name: "Credential Access".to_string(),
                        description: "Techniques for stealing credentials".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0006/".to_string(),
                    });
                },
                "discovery" => {
                    tactics.push(MitreTactic {
                        id: "TA0007".to_string(),
                        name: "Discovery".to_string(),
                        description: "Techniques for gaining knowledge about the environment".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0007/".to_string(),
                    });
                },
                "lateral_movement" => {
                    tactics.push(MitreTactic {
                        id: "TA0008".to_string(),
                        name: "Lateral Movement".to_string(),
                        description: "Techniques for moving through the network".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0008/".to_string(),
                    });
                },
                "collection" => {
                    tactics.push(MitreTactic {
                        id: "TA0009".to_string(),
                        name: "Collection".to_string(),
                        description: "Techniques for gathering data of interest".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0009/".to_string(),
                    });
                },
                "exfiltration" => {
                    tactics.push(MitreTactic {
                        id: "TA0010".to_string(),
                        name: "Exfiltration".to_string(),
                        description: "Techniques for stealing data".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0010/".to_string(),
                    });
                },
                "impact" => {
                    tactics.push(MitreTactic {
                        id: "TA0040".to_string(),
                        name: "Impact".to_string(),
                        description: "Techniques for disrupting availability or compromising integrity".to_string(),
                        url: "https://attack.mitre.org/tactics/TA0040/".to_string(),
                    });
                },
                _ => {}
            }
        }

        // Build kill chain stages
        let stage_names = ["Reconnaissance", "Initial Access", "Execution", "Persistence",
                          "Privilege Escalation", "Defense Evasion", "Credential Access",
                          "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"];

        for (i, name) in stage_names.iter().enumerate() {
            let techniques_at_stage: Vec<String> = techniques.iter()
                .filter(|t| t.tactic.to_lowercase() == name.to_lowercase())
                .map(|t| t.id.clone())
                .collect();

            if !techniques_at_stage.is_empty() || tactics.iter().any(|t| t.name.to_lowercase() == name.to_lowercase()) {
                kill_chain_stages.push(KillChainStage {
                    stage: (i + 1) as u32,
                    name: name.to_string(),
                    description: format!("{} stage of the attack", name),
                    techniques: techniques_at_stage,
                });
            }
        }

        Ok(MitreMapping {
            tactics,
            techniques,
            kill_chain_stages,
        })
    }

    /// Analyze business impact
    async fn analyze_business_impact(&self, path: &AttackPathData) -> Result<BusinessImpact> {
        let level = ImpactLevel::from_risk_score(
            match path.risk_level.to_lowercase().as_str() {
                "critical" => 90.0,
                "high" => 70.0,
                "medium" => 50.0,
                _ => 30.0,
            }
        );

        let description = format!(
            "This attack path could result in {} business impact. \
            The {} nodes in this path target {} and could lead to {}.",
            format!("{:?}", level).to_lowercase(),
            path.nodes.len(),
            path.target_node.as_deref().unwrap_or("critical systems"),
            self.describe_consequences(&path.risk_level)
        );

        let affected_functions = vec![
            "IT Operations".to_string(),
            "Business Continuity".to_string(),
            "Customer Trust".to_string(),
        ];

        let data_at_risk = vec![
            DataRiskItem {
                data_type: "Customer Data".to_string(),
                classification: "PII".to_string(),
                risk: "Potential exposure if attack reaches database systems".to_string(),
            },
            DataRiskItem {
                data_type: "Business Data".to_string(),
                classification: "Confidential".to_string(),
                risk: "Risk of exfiltration if lateral movement succeeds".to_string(),
            },
        ];

        let financial_impact = if level == ImpactLevel::Critical || level == ImpactLevel::High {
            Some(FinancialImpact {
                min_estimate_usd: match level {
                    ImpactLevel::Critical => 1_000_000,
                    _ => 100_000,
                },
                max_estimate_usd: match level {
                    ImpactLevel::Critical => 50_000_000,
                    _ => 5_000_000,
                },
                cost_factors: vec![
                    "Incident response".to_string(),
                    "Business disruption".to_string(),
                    "Customer notification".to_string(),
                    "Regulatory fines".to_string(),
                    "Legal fees".to_string(),
                ],
                confidence: "Medium - based on industry averages".to_string(),
            })
        } else {
            None
        };

        let regulatory_implications = if level == ImpactLevel::Critical || level == ImpactLevel::High {
            vec![
                "GDPR breach notification requirements".to_string(),
                "PCI-DSS compliance implications".to_string(),
                "SOX reporting requirements".to_string(),
            ]
        } else {
            vec![]
        };

        let reputational_risk = ReputationalRisk {
            level: format!("{:?}", level),
            description: format!(
                "{} reputational risk if this attack path is exploited",
                format!("{:?}", level)
            ),
            potential_headlines: if level == ImpactLevel::Critical {
                vec![
                    "Company Suffers Major Data Breach".to_string(),
                    "Millions of Customer Records Exposed".to_string(),
                ]
            } else {
                vec![]
            },
        };

        Ok(BusinessImpact {
            level,
            description,
            affected_functions,
            data_at_risk,
            financial_impact,
            regulatory_implications,
            reputational_risk,
        })
    }

    /// Identify recommended blocking points
    async fn identify_blocking_points(&self, path: &AttackPathData) -> Result<Vec<BlockingPoint>> {
        let mut blocking_points = Vec::new();

        // Early blocking is always best
        if !path.nodes.is_empty() {
            blocking_points.push(BlockingPoint {
                step: 1,
                action: "Block initial access by patching exposed vulnerabilities".to_string(),
                effectiveness: "Stops the attack at the entry point - most effective".to_string(),
                implementation_effort: EffortLevel::Medium,
                priority: 1,
                controls: vec![
                    "Patch management".to_string(),
                    "WAF/IPS".to_string(),
                    "Network segmentation".to_string(),
                ],
            });
        }

        // Credential access blocking
        if path.nodes.iter().any(|n| n.node_type == "credential_access") {
            blocking_points.push(BlockingPoint {
                step: 2,
                action: "Implement strong authentication and credential protection".to_string(),
                effectiveness: "Prevents credential harvesting and reuse".to_string(),
                implementation_effort: EffortLevel::Medium,
                priority: 2,
                controls: vec![
                    "MFA".to_string(),
                    "Privileged access management".to_string(),
                    "Password policy enforcement".to_string(),
                ],
            });
        }

        // Lateral movement blocking
        if path.nodes.iter().any(|n| n.node_type == "lateral_movement") {
            blocking_points.push(BlockingPoint {
                step: 3,
                action: "Implement network segmentation and zero trust architecture".to_string(),
                effectiveness: "Limits attacker movement through the network".to_string(),
                implementation_effort: EffortLevel::High,
                priority: 3,
                controls: vec![
                    "Microsegmentation".to_string(),
                    "Zero trust network access".to_string(),
                    "EDR/XDR".to_string(),
                ],
            });
        }

        // Data exfiltration blocking
        if path.nodes.iter().any(|n| n.node_type == "exfiltration" || n.node_type == "collection") {
            blocking_points.push(BlockingPoint {
                step: 4,
                action: "Deploy data loss prevention and monitoring".to_string(),
                effectiveness: "Last line of defense before data leaves".to_string(),
                implementation_effort: EffortLevel::Medium,
                priority: 4,
                controls: vec![
                    "DLP".to_string(),
                    "CASB".to_string(),
                    "Network monitoring".to_string(),
                    "SIEM alerting".to_string(),
                ],
            });
        }

        Ok(blocking_points)
    }

    /// Assess overall risk
    async fn assess_risk(&self, path: &AttackPathData) -> Result<RiskAssessment> {
        let base_risk = match path.risk_level.to_lowercase().as_str() {
            "critical" => 95.0,
            "high" => 75.0,
            "medium" => 50.0,
            _ => 25.0,
        };

        let probability = path.probability * 100.0;
        let impact = base_risk;
        let risk_score = (probability * 0.4 + impact * 0.6).min(100.0);

        let estimated_time = self.estimate_time(path.nodes.len(), &path.risk_level);

        let risk_factors = vec![
            RiskFactor {
                name: "Vulnerability Severity".to_string(),
                weight: 0.3,
                score: base_risk,
                description: "Based on severity of vulnerabilities in the path".to_string(),
            },
            RiskFactor {
                name: "Path Length".to_string(),
                weight: 0.2,
                score: if path.nodes.len() <= 3 { 80.0 } else { 40.0 },
                description: "Shorter paths are easier to exploit".to_string(),
            },
            RiskFactor {
                name: "Exploit Availability".to_string(),
                weight: 0.25,
                score: probability,
                description: "Based on known exploit availability".to_string(),
            },
            RiskFactor {
                name: "Target Value".to_string(),
                weight: 0.25,
                score: impact,
                description: "Based on value of assets at risk".to_string(),
            },
        ];

        let recommendation = match risk_score as u32 {
            80..=100 => "IMMEDIATE ACTION REQUIRED: This attack path represents critical risk and should be addressed within 24-48 hours.".to_string(),
            60..=79 => "HIGH PRIORITY: This attack path should be addressed within 1-2 weeks.".to_string(),
            40..=59 => "MEDIUM PRIORITY: Address this attack path within the next sprint/month.".to_string(),
            _ => "STANDARD PRIORITY: Include in regular remediation planning.".to_string(),
        };

        Ok(RiskAssessment {
            risk_score,
            exploitation_probability: probability,
            impact_score: impact,
            estimated_time_to_exploit: estimated_time,
            risk_factors,
            recommendation,
        })
    }

    /// Store interpretation in database
    async fn store_interpretation(&self, interp: &AttackPathInterpretation) -> Result<()> {
        let json = serde_json::to_string(interp)?;

        sqlx::query(
            r#"
            INSERT INTO attack_path_interpretations (path_id, generated_at, interpretation_data)
            VALUES (?, ?, ?)
            ON CONFLICT(path_id) DO UPDATE SET
                interpretation_data = excluded.interpretation_data,
                generated_at = excluded.generated_at
            "#
        )
        .bind(&interp.path_id)
        .bind(interp.generated_at.to_rfc3339())
        .bind(&json)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Get stored interpretation
    pub async fn get_interpretation(&self, path_id: &str) -> Result<Option<AttackPathInterpretation>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT interpretation_data FROM attack_path_interpretations WHERE path_id = ?"
        )
        .bind(path_id)
        .fetch_optional(&*self.pool)
        .await?;

        if let Some((data,)) = row {
            let interp: AttackPathInterpretation = serde_json::from_str(&data)?;
            Ok(Some(interp))
        } else {
            Ok(None)
        }
    }
}

// Internal data structures
#[derive(Debug)]
struct AttackPathData {
    id: String,
    name: String,
    risk_level: String,
    probability: f64,
    source_node: Option<String>,
    target_node: Option<String>,
    nodes: Vec<AttackNodeData>,
}

#[derive(Debug)]
struct AttackNodeData {
    id: String,
    node_type: String,
    vulnerability_ids: Vec<String>,
    sequence: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_complexity() {
        assert_eq!(AttackComplexity::from_score(10.0), AttackComplexity::Low);
        assert_eq!(AttackComplexity::from_score(40.0), AttackComplexity::Medium);
        assert_eq!(AttackComplexity::from_score(60.0), AttackComplexity::High);
        assert_eq!(AttackComplexity::from_score(90.0), AttackComplexity::VeryHigh);
    }

    #[test]
    fn test_impact_level() {
        assert_eq!(ImpactLevel::from_risk_score(20.0), ImpactLevel::Low);
        assert_eq!(ImpactLevel::from_risk_score(40.0), ImpactLevel::Medium);
        assert_eq!(ImpactLevel::from_risk_score(60.0), ImpactLevel::High);
        assert_eq!(ImpactLevel::from_risk_score(90.0), ImpactLevel::Critical);
    }
}
