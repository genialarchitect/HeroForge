//! AI Red Team Advisor - Analyzes network topology and generates attack recommendations
//!
//! Uses configurable LLM providers to analyze cATO network topology and generate actionable
//! red team recommendations with click-to-accept functionality.
//!
//! ## Provider Support
//!
//! The advisor uses the provider abstraction layer to support multiple LLM backends:
//! - Anthropic Claude (default, recommended for complex analysis)
//! - Ollama (self-hosted, good for air-gapped environments)
//! - OpenAI (planned)
//!
//! Configure via `LLM_PROVIDER` environment variable.

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::db::models::{
    AiRedTeamExecution, AiRedTeamRecommendation, AiRedTeamSession,
    AnalyzeTopologyRequest, RecommendationsSummary, RiskLevelCount, CategoryCount, TargetCount,
};

use super::providers::{BoxedProvider, LLMRequest, get_provider, LLMConfig};

/// Topology node for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    pub device_type: String,
    pub security_zone: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub compliance_status: String,
    pub vulnerabilities: Option<i32>,
    pub open_ports: Option<Vec<i32>>,
    pub services: Option<Vec<String>>,
}

/// Topology edge for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub encrypted: Option<bool>,
    pub data_classification: Option<String>,
}

/// Full topology for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyForAnalysis {
    pub nodes: Vec<TopologyNode>,
    pub edges: Vec<TopologyEdge>,
    pub metadata: Option<TopologyMetadata>,
}

/// Topology metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyMetadata {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub industry: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
}

/// AI-generated recommendation from Claude
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRecommendation {
    pub target_node_id: String,
    pub target_ip: Option<String>,
    pub target_hostname: Option<String>,
    pub target_type: String,
    pub action_type: String,
    pub action_category: String,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub mitre_technique_id: Option<String>,
    pub mitre_technique_name: Option<String>,
    pub mitre_tactic: Option<String>,
    pub risk_level: String,
    pub priority: i32,
    pub estimated_time_minutes: Option<i32>,
    pub prerequisites: Option<Vec<String>>,
    pub command_template: Option<String>,
    pub tool_name: Option<String>,
}

/// AI analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub session_id: String,
    pub recommendations: Vec<AiRedTeamRecommendation>,
    pub summary: AnalysisSummary,
}

/// Analysis summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_recommendations: i32,
    pub high_priority_count: i32,
    pub critical_targets: Vec<String>,
    pub suggested_attack_path: Option<Vec<String>>,
    pub key_findings: Vec<String>,
}

/// Red Team Advisor - Main analyzer
pub struct RedTeamAdvisor {
    pool: SqlitePool,
    provider: Option<BoxedProvider>,
}

impl RedTeamAdvisor {
    /// Create a new Red Team Advisor
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            provider: None,
        }
    }

    /// Create a Red Team Advisor with a specific provider
    pub fn with_provider(pool: SqlitePool, provider: BoxedProvider) -> Self {
        Self {
            pool,
            provider: Some(provider),
        }
    }

    /// Get or initialize the LLM provider
    async fn get_provider(&self) -> Result<BoxedProvider> {
        if let Some(ref provider) = self.provider {
            return Ok(provider.clone());
        }

        get_provider(None).await
            .map_err(|e| anyhow!("Failed to initialize LLM provider: {}", e))
    }

    /// Analyze topology and generate recommendations
    pub async fn analyze_topology(
        &self,
        user_id: &str,
        topology: TopologyForAnalysis,
        request: AnalyzeTopologyRequest,
    ) -> Result<AnalysisResult> {
        let session_id = Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();

        // Get the provider to determine model name
        let provider = self.get_provider().await?;
        let model_name = provider.default_model().to_string();

        // Create session record
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO ai_red_team_sessions (
                id, topology_id, scan_id, engagement_id, user_id, analysis_type,
                ai_model, recommendations_count, high_priority_count, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 'running', ?)
            "#,
        )
        .bind(&session_id)
        .bind(&request.topology_id)
        .bind(&request.scan_id)
        .bind(&request.engagement_id)
        .bind(user_id)
        .bind(request.analysis_type.as_deref().unwrap_or("full"))
        .bind(&model_name)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        // Generate recommendations using AI
        let generated = self.generate_recommendations(&topology, &request).await?;

        // Save recommendations to database
        let mut recommendations = Vec::new();
        let mut high_priority_count = 0;

        for rec in generated {
            let rec_id = Uuid::new_v4().to_string();
            let prerequisites_json = rec.prerequisites
                .map(|p| serde_json::to_string(&p).unwrap_or_default());

            if rec.priority >= 80 || rec.risk_level == "critical" || rec.risk_level == "high" {
                high_priority_count += 1;
            }

            sqlx::query(
                r#"
                INSERT INTO ai_red_team_recommendations (
                    id, topology_id, scan_id, engagement_id, user_id,
                    target_node_id, target_ip, target_hostname, target_type,
                    action_type, action_category, title, description, rationale,
                    mitre_technique_id, mitre_technique_name, mitre_tactic,
                    risk_level, priority, estimated_time_minutes,
                    prerequisites, command_template, tool_name, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                "#,
            )
            .bind(&rec_id)
            .bind(&request.topology_id)
            .bind(&request.scan_id)
            .bind(&request.engagement_id)
            .bind(user_id)
            .bind(&rec.target_node_id)
            .bind(&rec.target_ip)
            .bind(&rec.target_hostname)
            .bind(&rec.target_type)
            .bind(&rec.action_type)
            .bind(&rec.action_category)
            .bind(&rec.title)
            .bind(&rec.description)
            .bind(&rec.rationale)
            .bind(&rec.mitre_technique_id)
            .bind(&rec.mitre_technique_name)
            .bind(&rec.mitre_tactic)
            .bind(&rec.risk_level)
            .bind(rec.priority)
            .bind(rec.estimated_time_minutes)
            .bind(&prerequisites_json)
            .bind(&rec.command_template)
            .bind(&rec.tool_name)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            recommendations.push(AiRedTeamRecommendation {
                id: rec_id,
                topology_id: request.topology_id.clone(),
                scan_id: request.scan_id.clone(),
                engagement_id: request.engagement_id.clone(),
                user_id: user_id.to_string(),
                target_node_id: rec.target_node_id,
                target_ip: rec.target_ip,
                target_hostname: rec.target_hostname,
                target_type: rec.target_type,
                action_type: rec.action_type,
                action_category: rec.action_category,
                title: rec.title,
                description: rec.description,
                rationale: Some(rec.rationale),
                mitre_technique_id: rec.mitre_technique_id,
                mitre_technique_name: rec.mitre_technique_name,
                mitre_tactic: rec.mitre_tactic,
                risk_level: rec.risk_level,
                priority: rec.priority,
                estimated_time_minutes: rec.estimated_time_minutes,
                prerequisites: prerequisites_json,
                command_template: rec.command_template,
                tool_name: rec.tool_name,
                status: "pending".to_string(),
                accepted_at: None,
                rejected_at: None,
                executed_at: None,
                completed_at: None,
                execution_result: None,
                execution_output: None,
                created_at: now.clone(),
                updated_at: None,
            });
        }

        let duration_ms = start_time.elapsed().as_millis() as i32;
        let completed_at = Utc::now().to_rfc3339();

        // Update session with results
        sqlx::query(
            r#"
            UPDATE ai_red_team_sessions SET
                recommendations_count = ?,
                high_priority_count = ?,
                analysis_duration_ms = ?,
                status = 'completed',
                completed_at = ?
            WHERE id = ?
            "#,
        )
        .bind(recommendations.len() as i32)
        .bind(high_priority_count)
        .bind(duration_ms)
        .bind(&completed_at)
        .bind(&session_id)
        .execute(&self.pool)
        .await?;

        // Build summary
        let critical_targets: Vec<String> = recommendations
            .iter()
            .filter(|r| r.risk_level == "critical" || r.risk_level == "high")
            .map(|r| r.target_node_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let key_findings: Vec<String> = recommendations
            .iter()
            .filter(|r| r.priority >= 80)
            .take(5)
            .map(|r| r.title.clone())
            .collect();

        let total_recommendations = recommendations.len() as i32;

        Ok(AnalysisResult {
            session_id,
            recommendations,
            summary: AnalysisSummary {
                total_recommendations,
                high_priority_count,
                critical_targets,
                suggested_attack_path: None,
                key_findings,
            },
        })
    }

    /// Generate recommendations using the configured LLM provider
    async fn generate_recommendations(
        &self,
        topology: &TopologyForAnalysis,
        request: &AnalyzeTopologyRequest,
    ) -> Result<Vec<GeneratedRecommendation>> {
        let provider = self.get_provider().await?;

        // Build the prompt
        let prompt = self.build_analysis_prompt(topology, request);

        // Create the LLM request
        let llm_request = LLMRequest::new()
            .with_user_message(&prompt)
            .with_max_tokens(4096);

        // Call the LLM provider
        let response = provider.complete(llm_request).await
            .map_err(|e| anyhow!("LLM API error: {}", e))?;

        // Parse the JSON recommendations from the response
        self.parse_recommendations(&response.content, topology)
    }

    /// Build the analysis prompt for Claude
    fn build_analysis_prompt(&self, topology: &TopologyForAnalysis, request: &AnalyzeTopologyRequest) -> String {
        let topology_json = serde_json::to_string_pretty(topology).unwrap_or_default();
        let max_recommendations = request.max_recommendations.unwrap_or(20);
        let focus_areas = request.focus_areas.clone().unwrap_or_default();

        format!(r#"You are an expert red team operator and penetration tester. Analyze this network topology and generate specific, actionable attack recommendations.

## Network Topology
```json
{topology_json}
```

## Instructions
Generate up to {max_recommendations} attack recommendations. For each recommendation, provide:
1. The target node from the topology
2. Specific attack action to perform
3. MITRE ATT&CK technique mapping
4. Risk level (critical/high/medium/low)
5. Priority score (0-100)
6. Estimated time in minutes
7. Command templates where applicable
8. Prerequisites if any

{focus_instructions}

## Output Format
Respond ONLY with a JSON array of recommendations. Each recommendation must have this exact structure:
```json
[
  {{
    "target_node_id": "node-id-from-topology",
    "target_ip": "10.0.0.1",
    "target_hostname": "hostname",
    "target_type": "server|workstation|firewall|database|etc",
    "action_type": "scan|exploit|enumerate|credential_test|lateral_movement",
    "action_category": "reconnaissance|initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact",
    "title": "Brief action title",
    "description": "Detailed description of what to do",
    "rationale": "Why this target/action is important",
    "mitre_technique_id": "T1234",
    "mitre_technique_name": "Technique Name",
    "mitre_tactic": "Tactic Name",
    "risk_level": "critical|high|medium|low",
    "priority": 85,
    "estimated_time_minutes": 15,
    "prerequisites": ["prior action 1", "prior action 2"],
    "command_template": "nuclei -t cves/ -u {{{{target}}}}",
    "tool_name": "nuclei|nmap|hydra|etc"
  }}
]
```

Focus on:
- High-value targets (databases, domain controllers, EHR systems, medical devices)
- Entry points from DMZ or external zones
- Lateral movement opportunities
- Privilege escalation paths
- Data exfiltration risks
- Compliance violations (HIPAA, PCI-DSS, etc.)

Generate practical, safe-to-execute recommendations suitable for authorized penetration testing."#,
            topology_json = topology_json,
            max_recommendations = max_recommendations,
            focus_instructions = if focus_areas.is_empty() {
                String::new()
            } else {
                format!("Focus particularly on: {}", focus_areas.join(", "))
            }
        )
    }

    /// Parse recommendations from Claude's response
    fn parse_recommendations(&self, content: &str, topology: &TopologyForAnalysis) -> Result<Vec<GeneratedRecommendation>> {
        // Try to extract JSON from the response
        let json_str = if content.contains("```json") {
            content
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(content)
        } else if content.contains("```") {
            content
                .split("```")
                .nth(1)
                .unwrap_or(content)
        } else {
            content
        };

        let recommendations: Vec<GeneratedRecommendation> = serde_json::from_str(json_str.trim())
            .map_err(|e| anyhow!("Failed to parse recommendations: {} - Content: {}", e, json_str))?;

        // Validate that target_node_ids exist in topology
        let valid_node_ids: std::collections::HashSet<&str> = topology.nodes.iter()
            .map(|n| n.id.as_str())
            .collect();

        let validated: Vec<GeneratedRecommendation> = recommendations
            .into_iter()
            .filter(|r| valid_node_ids.contains(r.target_node_id.as_str()))
            .collect();

        Ok(validated)
    }

    /// Get recommendations for a topology/scan
    pub async fn get_recommendations(
        &self,
        user_id: &str,
        topology_id: Option<&str>,
        scan_id: Option<&str>,
        status: Option<&str>,
    ) -> Result<Vec<AiRedTeamRecommendation>> {
        let mut query = String::from(
            "SELECT * FROM ai_red_team_recommendations WHERE user_id = ?"
        );
        let mut params: Vec<String> = vec![user_id.to_string()];

        if let Some(tid) = topology_id {
            query.push_str(" AND topology_id = ?");
            params.push(tid.to_string());
        }
        if let Some(sid) = scan_id {
            query.push_str(" AND scan_id = ?");
            params.push(sid.to_string());
        }
        if let Some(s) = status {
            query.push_str(" AND status = ?");
            params.push(s.to_string());
        }

        query.push_str(" ORDER BY priority DESC, created_at DESC");

        // Use sqlx::query_as with explicit Sqlite type
        let results: Vec<AiRedTeamRecommendation> = sqlx::query_as::<sqlx::Sqlite, AiRedTeamRecommendation>(
            &format!(
                "SELECT * FROM ai_red_team_recommendations WHERE user_id = ?{}{}{} ORDER BY priority DESC, created_at DESC",
                topology_id.map(|_| " AND topology_id = ?").unwrap_or(""),
                scan_id.map(|_| " AND scan_id = ?").unwrap_or(""),
                status.map(|_| " AND status = ?").unwrap_or("")
            )
        )
        .bind(user_id)
        .bind(topology_id)
        .bind(scan_id)
        .bind(status)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Update recommendation status
    pub async fn update_recommendation_status(
        &self,
        recommendation_id: &str,
        user_id: &str,
        new_status: &str,
    ) -> Result<AiRedTeamRecommendation> {
        let now = Utc::now().to_rfc3339();

        let (accepted_at, rejected_at, executed_at) = match new_status {
            "accepted" => (Some(now.clone()), None, None),
            "rejected" => (None, Some(now.clone()), None),
            "running" => (None, None, Some(now.clone())),
            _ => (None, None, None),
        };

        sqlx::query(
            r#"
            UPDATE ai_red_team_recommendations SET
                status = ?,
                accepted_at = COALESCE(?, accepted_at),
                rejected_at = COALESCE(?, rejected_at),
                executed_at = COALESCE(?, executed_at),
                updated_at = ?
            WHERE id = ? AND user_id = ?
            "#,
        )
        .bind(new_status)
        .bind(&accepted_at)
        .bind(&rejected_at)
        .bind(&executed_at)
        .bind(&now)
        .bind(recommendation_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        let recommendation = sqlx::query_as::<_, AiRedTeamRecommendation>(
            "SELECT * FROM ai_red_team_recommendations WHERE id = ?"
        )
        .bind(recommendation_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(recommendation)
    }

    /// Get recommendations summary
    pub async fn get_summary(
        &self,
        user_id: &str,
        topology_id: Option<&str>,
        scan_id: Option<&str>,
    ) -> Result<RecommendationsSummary> {
        let base_filter = format!(
            "WHERE user_id = ?{}{}",
            topology_id.map(|_| " AND topology_id = ?").unwrap_or(""),
            scan_id.map(|_| " AND scan_id = ?").unwrap_or("")
        );

        // Total counts by status
        let status_counts: Vec<(String, i64)> = sqlx::query_as(
            &format!(
                "SELECT status, COUNT(*) as count FROM ai_red_team_recommendations {} GROUP BY status",
                base_filter
            )
        )
        .bind(user_id)
        .bind(topology_id)
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        let mut pending = 0i64;
        let mut accepted = 0i64;
        let mut rejected = 0i64;
        let mut running = 0i64;
        let mut completed = 0i64;
        let mut failed = 0i64;
        let mut total = 0i64;

        for (status, count) in status_counts {
            total += count;
            match status.as_str() {
                "pending" => pending = count,
                "accepted" => accepted = count,
                "rejected" => rejected = count,
                "running" => running = count,
                "completed" => completed = count,
                "failed" => failed = count,
                _ => {}
            }
        }

        // By risk level
        let by_risk_level: Vec<RiskLevelCount> = sqlx::query_as(
            &format!(
                "SELECT risk_level, COUNT(*) as count FROM ai_red_team_recommendations {} GROUP BY risk_level ORDER BY CASE risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END",
                base_filter
            )
        )
        .bind(user_id)
        .bind(topology_id)
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        // By category
        let by_category: Vec<CategoryCount> = sqlx::query_as(
            &format!(
                "SELECT action_category as category, COUNT(*) as count FROM ai_red_team_recommendations {} GROUP BY action_category ORDER BY count DESC",
                base_filter
            )
        )
        .bind(user_id)
        .bind(topology_id)
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        // By target
        let by_target: Vec<TargetCount> = sqlx::query_as(
            &format!(
                "SELECT target_node_id, target_ip, target_hostname, COUNT(*) as count FROM ai_red_team_recommendations {} GROUP BY target_node_id ORDER BY count DESC LIMIT 10",
                base_filter
            )
        )
        .bind(user_id)
        .bind(topology_id)
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(RecommendationsSummary {
            total,
            pending,
            accepted,
            rejected,
            running,
            completed,
            failed,
            by_risk_level,
            by_category,
            by_target,
        })
    }

    /// Accept all pending recommendations
    pub async fn accept_all(&self, user_id: &str, topology_id: Option<&str>) -> Result<i64> {
        let now = Utc::now().to_rfc3339();

        let result = sqlx::query(
            r#"
            UPDATE ai_red_team_recommendations SET
                status = 'accepted',
                accepted_at = ?,
                updated_at = ?
            WHERE user_id = ? AND status = 'pending'
            AND (? IS NULL OR topology_id = ?)
            "#,
        )
        .bind(&now)
        .bind(&now)
        .bind(user_id)
        .bind(&topology_id)
        .bind(&topology_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Reject all pending recommendations
    pub async fn reject_all(&self, user_id: &str, topology_id: Option<&str>) -> Result<i64> {
        let now = Utc::now().to_rfc3339();

        let result = sqlx::query(
            r#"
            UPDATE ai_red_team_recommendations SET
                status = 'rejected',
                rejected_at = ?,
                updated_at = ?
            WHERE user_id = ? AND status = 'pending'
            AND (? IS NULL OR topology_id = ?)
            "#,
        )
        .bind(&now)
        .bind(&now)
        .bind(user_id)
        .bind(&topology_id)
        .bind(&topology_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }
}
