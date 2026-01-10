//! LLM-powered Security Operations Orchestrator
//!
//! Provides AI-powered features using Claude API:
//! - Automated report generation (executive & technical)
//! - Intelligent scan planning
//! - Exploit code analysis
//! - Security policy generation
//! - Remediation guidance

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::types::HostInfo;

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MODEL: &str = "claude-3-5-sonnet-20241022";

/// LLM Orchestrator for security operations
pub struct LLMOrchestrator {
    api_key: String,
    client: Client,
}

/// Claude API request structure
#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<Message>,
}

#[derive(Debug, Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: String,
}

// Report types
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutiveReport {
    pub summary: String,
    pub risk_score: f64,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TechnicalReport {
    pub technical_summary: String,
    pub vulnerability_breakdown: Vec<String>,
    pub remediation_roadmap: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanPlan {
    pub recommended_scans: Vec<String>,
    pub estimated_duration: String,
    pub risk_factors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExploitAnalysis {
    pub vulnerability_id: String,
    pub attack_flow: String,
    pub impact_assessment: String,
    pub mitigations: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub title: String,
    pub content: String,
    pub review_schedule: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemediationGuidance {
    pub immediate_actions: Vec<String>,
    pub detailed_steps: Vec<String>,
    pub tools_required: Vec<String>,
    pub estimated_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyType {
    AccessControl,
    DataProtection,
    IncidentResponse,
    ChangeManagement,
    AssetManagement,
    VulnerabilityManagement,
    NetworkSecurity,
    CloudSecurity,
}

impl LLMOrchestrator {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: Client::new(),
        }
    }

    async fn call_claude(&self, system: &str, user_prompt: &str) -> Result<String> {
        let request = ClaudeRequest {
            model: MODEL.to_string(),
            max_tokens: 4096,
            system: system.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: user_prompt.to_string(),
            }],
        };

        let response = self
            .client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Claude API error {}: {}", status, error_text));
        }

        let claude_response: ClaudeResponse = response.json().await?;

        let text = claude_response
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        Ok(text)
    }

    /// Generate an executive summary report
    pub async fn generate_executive_report(&self, scan_results: &[HostInfo]) -> Result<ExecutiveReport> {
        let system = "You are a cybersecurity expert writing executive-level security reports for C-suite leaders.";

        let results_summary = format!(
            "Scanned {} hosts with {} total open ports",
            scan_results.len(),
            scan_results.iter().map(|h| h.ports.len()).sum::<usize>()
        );

        let prompt = format!(
            "Create an executive security report summary based on these scan results:\n\n{}\n\nFormat as JSON with fields: summary (string), risk_score (0.0-10.0), key_findings (array), recommendations (array)",
            results_summary
        );

        let response = self.call_claude(system, &prompt).await?;

        // Try to parse as JSON, or create a structured response
        serde_json::from_str(&response).or_else(|_| {
            Ok(ExecutiveReport {
                summary: response.clone(),
                risk_score: 5.0,
                key_findings: vec!["See full report for details".to_string()],
                recommendations: vec!["Review findings and prioritize remediation".to_string()],
            })
        })
    }

    /// Generate a technical security report
    pub async fn generate_technical_report(&self, scan_results: &[HostInfo]) -> Result<TechnicalReport> {
        let system = "You are a penetration testing expert writing technical security reports for security engineers.";

        let results_summary = serde_json::to_string_pretty(scan_results)?;

        let prompt = format!(
            "Create a technical security report based on these scan results:\n\n{}\n\nFormat as JSON with fields: technical_summary (string), vulnerability_breakdown (array), remediation_roadmap (array)",
            results_summary
        );

        let response = self.call_claude(system, &prompt).await?;

        serde_json::from_str(&response).or_else(|_| {
            Ok(TechnicalReport {
                technical_summary: response.clone(),
                vulnerability_breakdown: vec![],
                remediation_roadmap: vec![],
            })
        })
    }

    /// Generate intelligent scan plan
    pub async fn plan_scan(&self, targets: &[String], objectives: &[String]) -> Result<ScanPlan> {
        let system = "You are a penetration testing expert creating optimized scan plans.";

        let prompt = format!(
            "Create an intelligent scan plan for:\nTargets: {}\nObjectives: {}\n\nFormat as JSON with fields: recommended_scans (array), estimated_duration (string), risk_factors (array)",
            targets.join(", "),
            objectives.join(", ")
        );

        let response = self.call_claude(system, &prompt).await?;

        serde_json::from_str(&response).or_else(|_| {
            Ok(ScanPlan {
                recommended_scans: vec!["Comprehensive TCP scan".to_string()],
                estimated_duration: "1-2 hours".to_string(),
                risk_factors: vec![],
            })
        })
    }

    /// Analyze exploit code
    pub async fn analyze_exploit(&self, code: &str, context: Option<&str>) -> Result<ExploitAnalysis> {
        let system = "You are a malware analysis and exploit research expert.";

        let prompt = format!(
            "Analyze this exploit code:\n\n```\n{}\n```\n\nContext: {}\n\nFormat as JSON with fields: vulnerability_id (string), attack_flow (string), impact_assessment (string), mitigations (array), mitre_techniques (array)",
            code,
            context.unwrap_or("No additional context")
        );

        let response = self.call_claude(system, &prompt).await?;

        serde_json::from_str(&response).or_else(|_| {
            Ok(ExploitAnalysis {
                vulnerability_id: "Unknown".to_string(),
                attack_flow: response.clone(),
                impact_assessment: "See analysis for details".to_string(),
                mitigations: vec![],
                mitre_techniques: vec![],
            })
        })
    }

    /// Generate security policy
    pub async fn generate_security_policy(
        &self,
        policy_type: PolicyType,
        organization: &str,
        frameworks: &[String],
    ) -> Result<SecurityPolicy> {
        let system = "You are a security compliance expert writing organizational security policies.";

        let prompt = format!(
            "Generate a {:?} security policy for {} organization, aligned with {} frameworks.\n\nFormat as JSON with fields: title (string), content (string, markdown formatted), review_schedule (string)",
            policy_type,
            organization,
            frameworks.join(", ")
        );

        let response = self.call_claude(system, &prompt).await?;

        serde_json::from_str(&response).or_else(|_| {
            Ok(SecurityPolicy {
                title: format!("{:?} Policy", policy_type),
                content: response.clone(),
                review_schedule: "Annually".to_string(),
            })
        })
    }

    /// Generate remediation guidance
    pub async fn generate_remediation_guidance(
        &self,
        vulnerability: &str,
        context: &str,
    ) -> Result<RemediationGuidance> {
        let system = "You are a security remediation expert providing step-by-step fix guidance.";

        let prompt = format!(
            "Provide remediation guidance for:\nVulnerability: {}\nContext: {}\n\nFormat as JSON with fields: immediate_actions (array), detailed_steps (array), tools_required (array), estimated_time (string)",
            vulnerability,
            context
        );

        let response = self.call_claude(system, &prompt).await?;

        serde_json::from_str(&response).or_else(|_| {
            Ok(RemediationGuidance {
                immediate_actions: vec!["Review vulnerability details".to_string()],
                detailed_steps: vec![response.clone()],
                tools_required: vec![],
                estimated_time: "Varies".to_string(),
            })
        })
    }
}

/// Quick standalone chat function for simple AI queries
///
/// This function creates a temporary client and makes a single API call.
/// For repeated use, prefer creating an LLMOrchestrator instance.
pub async fn quick_chat(system_prompt: &str, user_message: &str) -> Result<String> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .map_err(|_| anyhow!("ANTHROPIC_API_KEY not set"))?;

    let client = Client::new();

    let request = ClaudeRequest {
        model: MODEL.to_string(),
        max_tokens: 1024,
        system: system_prompt.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: user_message.to_string(),
        }],
    };

    let response = client
        .post(ANTHROPIC_API_URL)
        .header("x-api-key", &api_key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header("content-type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!("API request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("API error {}: {}", status, body));
    }

    let claude_response: ClaudeResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse response: {}", e))?;

    claude_response
        .content
        .first()
        .map(|c| c.text.clone())
        .ok_or_else(|| anyhow!("No content in response"))
}
