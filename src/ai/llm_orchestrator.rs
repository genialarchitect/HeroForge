//! LLM-powered Security Operations Orchestrator
//!
//! Provides AI-powered features using configurable LLM providers:
//! - Automated report generation (executive & technical)
//! - Intelligent scan planning
//! - Exploit code analysis
//! - Security policy generation
//! - Remediation guidance
//!
//! ## Provider Support
//!
//! The orchestrator uses the provider abstraction layer to support multiple LLM backends:
//! - Anthropic Claude (default)
//! - Ollama (self-hosted)
//! - OpenAI (planned)
//!
//! Configure via `LLM_PROVIDER` environment variable.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::types::HostInfo;

use super::providers::{
    BoxedProvider, LLMRequest, LLMMessage, LLMError,
    get_provider, LLMConfig,
};

/// LLM Orchestrator for security operations
///
/// Uses the provider abstraction layer for LLM interactions,
/// allowing seamless switching between Claude, Ollama, and other providers.
pub struct LLMOrchestrator {
    provider: BoxedProvider,
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
    /// Create a new orchestrator with the default configured provider
    pub async fn new() -> Result<Self> {
        let provider = get_provider(None).await
            .map_err(|e| anyhow!("Failed to initialize LLM provider: {}", e))?;

        Ok(Self { provider })
    }

    /// Create orchestrator with a specific provider
    pub fn with_provider(provider: BoxedProvider) -> Self {
        Self { provider }
    }

    /// Create orchestrator with custom configuration
    pub async fn with_config(config: &LLMConfig) -> Result<Self> {
        let provider = get_provider(Some(config)).await
            .map_err(|e| anyhow!("Failed to initialize LLM provider: {}", e))?;

        Ok(Self { provider })
    }

    /// Create from API key (backwards compatibility)
    ///
    /// This method is provided for backwards compatibility with existing code.
    /// New code should use `new()` or `with_config()` instead.
    #[deprecated(note = "Use new() or with_config() instead")]
    pub async fn from_api_key(_api_key: String) -> Result<Self> {
        Self::new().await
    }

    /// Legacy constructor (backwards compatibility)
    #[allow(clippy::new_ret_no_self)]
    pub fn new_sync(api_key: String) -> LLMOrchestratorLegacy {
        LLMOrchestratorLegacy::new(api_key)
    }

    /// Get the provider name
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Get the model being used
    pub fn model(&self) -> &str {
        self.provider.default_model()
    }

    /// Send a prompt to the LLM and get a response
    async fn call_llm(&self, system: &str, user_prompt: &str) -> Result<String> {
        let request = LLMRequest::new()
            .with_system_prompt(system)
            .with_user_message(user_prompt)
            .with_max_tokens(4096);

        let response = self.provider.complete(request).await
            .map_err(|e| match e {
                LLMError::NotConfigured(msg) => anyhow!("LLM not configured: {}", msg),
                LLMError::ApiError { status, message } => anyhow!("LLM API error {}: {}", status, message),
                LLMError::RateLimited { .. } => anyhow!("LLM rate limited, try again later"),
                LLMError::ModelNotFound(model) => anyhow!("Model not found: {}", model),
                LLMError::Unavailable(msg) => anyhow!("LLM unavailable: {}", msg),
                _ => anyhow!("LLM error: {}", e),
            })?;

        Ok(response.content)
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

        let response = self.call_llm(system, &prompt).await?;

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

        let response = self.call_llm(system, &prompt).await?;

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

        let response = self.call_llm(system, &prompt).await?;

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

        let response = self.call_llm(system, &prompt).await?;

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

        let response = self.call_llm(system, &prompt).await?;

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

        let response = self.call_llm(system, &prompt).await?;

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

/// Legacy orchestrator for backwards compatibility
///
/// This struct maintains the old synchronous-looking API that creates
/// a reqwest client directly. New code should use `LLMOrchestrator` instead.
pub struct LLMOrchestratorLegacy {
    api_key: String,
    client: reqwest::Client,
}

impl LLMOrchestratorLegacy {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
        }
    }

    async fn call_claude(&self, system: &str, user_prompt: &str) -> Result<String> {
        use serde_json::json;

        const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
        const ANTHROPIC_VERSION: &str = "2023-06-01";
        const MODEL: &str = "claude-sonnet-4-20250514";

        let request = json!({
            "model": MODEL,
            "max_tokens": 4096,
            "system": system,
            "messages": [{
                "role": "user",
                "content": user_prompt
            }]
        });

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

        #[derive(Deserialize)]
        struct ClaudeResponse {
            content: Vec<ContentBlock>,
        }

        #[derive(Deserialize)]
        struct ContentBlock {
            text: String,
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
}

/// Quick standalone chat function for simple AI queries
///
/// This function uses the configured provider to make a single API call.
/// For repeated use, prefer creating an LLMOrchestrator instance.
pub async fn quick_chat(system_prompt: &str, user_message: &str) -> Result<String> {
    let provider = get_provider(None).await
        .map_err(|e| anyhow!("LLM provider not available: {}", e))?;

    let request = LLMRequest::new()
        .with_system_prompt(system_prompt)
        .with_user_message(user_message)
        .with_max_tokens(1024);

    let response = provider.complete(request).await
        .map_err(|e| anyhow!("LLM request failed: {}", e))?;

    Ok(response.content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_debug() {
        let policy = PolicyType::AccessControl;
        assert!(format!("{:?}", policy).contains("AccessControl"));
    }
}
