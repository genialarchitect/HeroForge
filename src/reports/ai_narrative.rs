//! AI-Generated Report Narratives
//!
//! This module provides AI-powered narrative generation for security reports,
//! creating compelling, stakeholder-appropriate summaries and recommendations.
//!
//! Features:
//! - Executive summaries with business impact
//! - Risk contextualization ("why this matters")
//! - Remediation priority rationale
//! - Plain-language technical explanations
//! - Audience-specific content (executive vs technical)

use anyhow::{anyhow, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ai::providers::{get_provider, LLMMessage, LLMProvider, LLMRequest};
use crate::types::Severity;

use super::types::{FindingDetail, ReportData, ReportSummary};

/// AI-generated narrative sections for a report
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AINarrative {
    /// Executive summary for non-technical stakeholders
    pub executive_summary: Option<String>,

    /// Technical summary for security teams
    pub technical_summary: Option<String>,

    /// Business impact analysis
    pub business_impact: Option<String>,

    /// Key risk insights and context
    pub risk_insights: Vec<String>,

    /// Prioritized remediation rationale
    pub remediation_rationale: Option<String>,

    /// Attack scenario descriptions
    pub attack_scenarios: Vec<AttackScenario>,

    /// Compliance implications
    pub compliance_implications: Option<String>,

    /// AI confidence score (0-100)
    pub confidence_score: u8,

    /// Generation timestamp
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// An attack scenario narrative
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    /// Scenario title
    pub title: String,

    /// "An attacker could..." narrative
    pub narrative: String,

    /// Affected assets
    pub affected_assets: Vec<String>,

    /// Related vulnerabilities
    pub related_vulnerabilities: Vec<String>,

    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,

    /// Potential business impact
    pub impact: String,

    /// Recommended blocking points
    pub blocking_points: Vec<String>,
}

/// Audience type for narrative generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceType {
    /// C-suite executives, board members
    Executive,
    /// IT managers, security team leads
    Management,
    /// Security engineers, developers
    Technical,
    /// External auditors, compliance officers
    Compliance,
}

/// Options for AI narrative generation
#[derive(Debug, Clone)]
pub struct NarrativeOptions {
    /// Target audience
    pub audience: AudienceType,

    /// Include attack scenarios
    pub include_attack_scenarios: bool,

    /// Include compliance implications
    pub include_compliance: bool,

    /// Maximum length for summaries (characters)
    pub max_summary_length: usize,

    /// Company/organization name for context
    pub organization_name: Option<String>,

    /// Industry context (healthcare, finance, etc.)
    pub industry: Option<String>,
}

impl Default for NarrativeOptions {
    fn default() -> Self {
        Self {
            audience: AudienceType::Executive,
            include_attack_scenarios: true,
            include_compliance: true,
            max_summary_length: 2000,
            organization_name: None,
            industry: None,
        }
    }
}

/// AI Narrative Generator
pub struct NarrativeGenerator {
    options: NarrativeOptions,
}

impl NarrativeGenerator {
    /// Create a new narrative generator with options
    pub fn new(options: NarrativeOptions) -> Self {
        Self { options }
    }

    /// Create with default options
    pub fn default_generator() -> Self {
        Self::new(NarrativeOptions::default())
    }

    /// Generate comprehensive AI narrative for a report
    pub async fn generate(&self, report_data: &ReportData) -> Result<AINarrative> {
        info!("Generating AI narrative for report: {}", report_data.name);

        let provider = match get_provider(None).await {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to get LLM provider: {}. Returning fallback narrative.", e);
                return Ok(self.generate_fallback_narrative(report_data));
            }
        };

        let mut narrative = AINarrative {
            generated_at: chrono::Utc::now(),
            ..Default::default()
        };

        // Generate executive summary
        match self.generate_executive_summary(&provider, report_data).await {
            Ok(summary) => narrative.executive_summary = Some(summary),
            Err(e) => warn!("Failed to generate executive summary: {}", e),
        }

        // Generate technical summary
        match self.generate_technical_summary(&provider, report_data).await {
            Ok(summary) => narrative.technical_summary = Some(summary),
            Err(e) => warn!("Failed to generate technical summary: {}", e),
        }

        // Generate business impact analysis
        match self.generate_business_impact(&provider, report_data).await {
            Ok(impact) => narrative.business_impact = Some(impact),
            Err(e) => warn!("Failed to generate business impact: {}", e),
        }

        // Generate risk insights
        match self.generate_risk_insights(&provider, report_data).await {
            Ok(insights) => narrative.risk_insights = insights,
            Err(e) => warn!("Failed to generate risk insights: {}", e),
        }

        // Generate remediation rationale
        match self.generate_remediation_rationale(&provider, report_data).await {
            Ok(rationale) => narrative.remediation_rationale = Some(rationale),
            Err(e) => warn!("Failed to generate remediation rationale: {}", e),
        }

        // Generate attack scenarios if enabled
        if self.options.include_attack_scenarios {
            match self.generate_attack_scenarios(&provider, report_data).await {
                Ok(scenarios) => narrative.attack_scenarios = scenarios,
                Err(e) => warn!("Failed to generate attack scenarios: {}", e),
            }
        }

        // Generate compliance implications if enabled
        if self.options.include_compliance {
            match self.generate_compliance_implications(&provider, report_data).await {
                Ok(implications) => narrative.compliance_implications = Some(implications),
                Err(e) => warn!("Failed to generate compliance implications: {}", e),
            }
        }

        // Calculate confidence score based on what was generated
        narrative.confidence_score = self.calculate_confidence(&narrative);

        info!(
            "AI narrative generated with confidence score: {}",
            narrative.confidence_score
        );

        Ok(narrative)
    }

    /// Generate executive summary
    async fn generate_executive_summary(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<String> {
        let context = self.build_summary_context(report_data);
        let org_context = self.build_organization_context();

        let prompt = format!(
            r#"You are a cybersecurity expert writing an executive summary for a security assessment report.

{}

## Assessment Data
{}

## Instructions
Write a clear, concise executive summary (2-3 paragraphs) that:
1. States the overall security posture in business terms
2. Highlights the most critical risks and their potential business impact
3. Provides a high-level view of recommended actions
4. Avoids technical jargon - this is for executives who need to understand risk, not implementation details

Focus on business impact: financial risk, operational disruption, reputational damage, regulatory exposure.

Do NOT include:
- Technical details about specific vulnerabilities
- CVE numbers or technical identifiers
- Implementation-level recommendations
- Excessive length (keep it under 300 words)

Write the executive summary now:"#,
            org_context, context
        );

        self.call_llm(provider, &prompt).await
    }

    /// Generate technical summary
    async fn generate_technical_summary(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<String> {
        let context = self.build_technical_context(report_data);

        let prompt = format!(
            r#"You are a senior security engineer writing a technical summary for a penetration test report.

## Assessment Data
{}

## Instructions
Write a technical summary (3-4 paragraphs) that:
1. Describes the scope and methodology of the assessment
2. Summarizes key technical findings with appropriate detail
3. Identifies patterns or systemic issues in the security posture
4. Highlights critical vulnerabilities that require immediate attention
5. Notes any positive security controls that were effective

Include relevant technical details but remain accessible to IT professionals who may not be security specialists.

Write the technical summary now:"#,
            context
        );

        self.call_llm(provider, &prompt).await
    }

    /// Generate business impact analysis
    async fn generate_business_impact(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<String> {
        let context = self.build_vulnerability_context(report_data);
        let org_context = self.build_organization_context();

        let prompt = format!(
            r#"You are a risk analyst assessing the business impact of security vulnerabilities.

{}

## Vulnerability Summary
{}

## Instructions
Write a business impact analysis (2-3 paragraphs) that explains:
1. What could happen to the business if these vulnerabilities are exploited
2. Specific types of data or systems at risk
3. Potential regulatory or compliance consequences
4. Estimated severity of financial and operational impact

Use concrete examples and scenarios. Avoid speculative worst-case scenarios but be realistic about genuine risks.

Write the business impact analysis now:"#,
            org_context, context
        );

        self.call_llm(provider, &prompt).await
    }

    /// Generate risk insights
    async fn generate_risk_insights(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<Vec<String>> {
        let context = self.build_vulnerability_context(report_data);

        let prompt = format!(
            r#"You are a security risk analyst providing key insights about vulnerabilities.

## Vulnerability Data
{}

## Instructions
Provide 4-6 key risk insights as bullet points. Each insight should:
1. Identify a specific risk pattern or concern
2. Explain why it matters ("because...")
3. Be actionable or informative

Format: Return ONLY the bullet points, one per line, starting with "- ".

Example format:
- Critical services are exposed to the internet without proper authentication, increasing the risk of unauthorized access
- Multiple systems share default credentials, enabling lateral movement if any single system is compromised

Write the risk insights now:"#,
            context
        );

        let response = self.call_llm(provider, &prompt).await?;

        // Parse bullet points
        let insights: Vec<String> = response
            .lines()
            .filter(|line| line.trim().starts_with('-') || line.trim().starts_with('•'))
            .map(|line| line.trim().trim_start_matches('-').trim_start_matches('•').trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(insights)
    }

    /// Generate remediation rationale
    async fn generate_remediation_rationale(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<String> {
        let context = self.build_remediation_context(report_data);

        let prompt = format!(
            r#"You are a security consultant explaining remediation priorities.

## Findings and Remediation Data
{}

## Instructions
Write a remediation rationale (2-3 paragraphs) that explains:
1. Why the recommended priority order makes sense
2. Which fixes provide the most security improvement per effort
3. Dependencies between fixes (what should be done first)
4. Quick wins vs. longer-term improvements

Help the reader understand not just what to fix, but why to fix it in the recommended order.

Write the remediation rationale now:"#,
            context
        );

        self.call_llm(provider, &prompt).await
    }

    /// Generate attack scenarios
    async fn generate_attack_scenarios(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<Vec<AttackScenario>> {
        let context = self.build_vulnerability_context(report_data);

        let prompt = format!(
            r#"You are a red team operator describing realistic attack scenarios.

## Vulnerability Data
{}

## Instructions
Describe 2-3 realistic attack scenarios based on the discovered vulnerabilities.

For each scenario, provide:
1. A short title
2. A narrative starting with "An attacker could..."
3. The potential business impact
4. 1-2 recommended blocking points to prevent this attack

Format each scenario as:
SCENARIO: [Title]
NARRATIVE: An attacker could...
IMPACT: [Business impact]
BLOCKING: [Comma-separated blocking points]

---

Write the attack scenarios now:"#,
            context
        );

        let response = self.call_llm(provider, &prompt).await?;

        // Parse scenarios from response
        let scenarios = self.parse_attack_scenarios(&response, report_data);

        Ok(scenarios)
    }

    /// Generate compliance implications
    async fn generate_compliance_implications(
        &self,
        provider: &Arc<dyn LLMProvider>,
        report_data: &ReportData,
    ) -> Result<String> {
        let context = self.build_vulnerability_context(report_data);
        let org_context = self.build_organization_context();

        let prompt = format!(
            r#"You are a compliance expert assessing the regulatory implications of security findings.

{}

## Security Findings
{}

## Instructions
Write a compliance implications section (2-3 paragraphs) that addresses:
1. Which regulations or standards these findings may impact (PCI-DSS, HIPAA, SOC 2, GDPR, etc.)
2. Specific control failures or gaps
3. Potential audit or compliance consequences
4. Recommended compliance-focused remediation priorities

Be specific about which findings relate to which compliance requirements.

Write the compliance implications now:"#,
            org_context, context
        );

        self.call_llm(provider, &prompt).await
    }

    /// Call the LLM provider with a prompt
    async fn call_llm(
        &self,
        provider: &Arc<dyn LLMProvider>,
        prompt: &str,
    ) -> Result<String> {
        let request = LLMRequest {
            system_prompt: Some("You are a professional cybersecurity consultant with expertise in risk assessment, penetration testing, and security reporting. You write clear, actionable content for various audiences.".to_string()),
            messages: vec![LLMMessage::user(prompt)],
            max_tokens: 2000,
            temperature: Some(0.7),
            stream: false,
            model: None,
        };

        let response = provider
            .complete(request)
            .await
            .map_err(|e| anyhow!("LLM completion failed: {:?}", e))?;

        Ok(response.content)
    }

    /// Build summary context from report data
    fn build_summary_context(&self, report_data: &ReportData) -> String {
        let summary = &report_data.summary;

        format!(
            r#"- Total hosts scanned: {}
- Live hosts: {}
- Open ports: {}
- Critical vulnerabilities: {}
- High vulnerabilities: {}
- Medium vulnerabilities: {}
- Low vulnerabilities: {}
- Total vulnerabilities: {}
- Overall risk level: {} (score: {})"#,
            summary.total_hosts,
            summary.live_hosts,
            summary.open_ports,
            summary.critical_count,
            summary.high_count,
            summary.medium_count,
            summary.low_count,
            summary.total_vulnerabilities,
            summary.overall_risk_level,
            summary.overall_risk_score
        )
    }

    /// Build technical context from report data
    fn build_technical_context(&self, report_data: &ReportData) -> String {
        let mut context = self.build_summary_context(report_data);

        // Add top findings
        context.push_str("\n\n## Top Findings:\n");
        for (i, finding) in report_data.findings.iter().take(10).enumerate() {
            context.push_str(&format!(
                "{}. [{}] {} - {}\n",
                i + 1,
                severity_to_string(&finding.severity),
                finding.title,
                finding.affected_hosts.len()
            ));
        }

        // Add common services
        context.push_str("\n## Services Detected:\n");
        let mut services: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for host in &report_data.hosts {
            for port in &host.ports {
                if let Some(ref svc) = port.service {
                    *services.entry(svc.name.clone()).or_insert(0) += 1;
                }
            }
        }
        for (service, count) in services.iter().take(10) {
            context.push_str(&format!("- {}: {} instances\n", service, count));
        }

        context
    }

    /// Build vulnerability context from report data
    fn build_vulnerability_context(&self, report_data: &ReportData) -> String {
        let mut context = String::new();

        // Group by severity
        let critical: Vec<_> = report_data
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .collect();
        let high: Vec<_> = report_data
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .collect();

        if !critical.is_empty() {
            context.push_str("## Critical Vulnerabilities:\n");
            for finding in critical.iter().take(5) {
                context.push_str(&format!(
                    "- {}: {} ({} affected hosts)\n",
                    finding.title,
                    finding.description.chars().take(100).collect::<String>(),
                    finding.affected_hosts.len()
                ));
            }
        }

        if !high.is_empty() {
            context.push_str("\n## High Vulnerabilities:\n");
            for finding in high.iter().take(5) {
                context.push_str(&format!(
                    "- {}: {} ({} affected hosts)\n",
                    finding.title,
                    finding.description.chars().take(100).collect::<String>(),
                    finding.affected_hosts.len()
                ));
            }
        }

        context.push_str(&format!(
            "\n## Summary: {} critical, {} high, {} medium, {} low\n",
            critical.len(),
            high.len(),
            report_data.findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count(),
            report_data.findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count()
        ));

        context
    }

    /// Build remediation context from report data
    fn build_remediation_context(&self, report_data: &ReportData) -> String {
        let mut context = String::new();

        context.push_str("## Remediation Recommendations (by priority):\n\n");

        for (i, rec) in report_data.remediation.iter().take(10).enumerate() {
            context.push_str(&format!(
                "{}. [Priority: {}] {}\n   - Description: {}\n   - Effort: {}\n   - Timeline: {}\n\n",
                i + 1,
                rec.priority,
                rec.title,
                rec.description,
                rec.effort_estimate,
                rec.timeline_suggestion
            ));
        }

        context
    }

    /// Build organization context string
    fn build_organization_context(&self) -> String {
        let mut context = String::new();

        if let Some(ref org) = self.options.organization_name {
            context.push_str(&format!("## Organization: {}\n", org));
        }

        if let Some(ref industry) = self.options.industry {
            context.push_str(&format!("## Industry: {}\n", industry));
        }

        if !context.is_empty() {
            context.push_str("\n");
        }

        context
    }

    /// Parse attack scenarios from LLM response
    fn parse_attack_scenarios(&self, response: &str, _report_data: &ReportData) -> Vec<AttackScenario> {
        let mut scenarios = Vec::new();

        // Split by scenario markers
        let parts: Vec<&str> = response.split("SCENARIO:").collect();

        for part in parts.iter().skip(1) {
            let mut title = String::new();
            let mut narrative = String::new();
            let mut impact = String::new();
            let mut blocking_points = Vec::new();

            for line in part.lines() {
                let line = line.trim();
                if line.starts_with("NARRATIVE:") {
                    narrative = line.trim_start_matches("NARRATIVE:").trim().to_string();
                } else if line.starts_with("IMPACT:") {
                    impact = line.trim_start_matches("IMPACT:").trim().to_string();
                } else if line.starts_with("BLOCKING:") {
                    let bp = line.trim_start_matches("BLOCKING:").trim();
                    blocking_points = bp.split(',').map(|s| s.trim().to_string()).collect();
                } else if title.is_empty() && !line.is_empty() && !line.starts_with("---") {
                    title = line.to_string();
                }
            }

            if !title.is_empty() && !narrative.is_empty() {
                scenarios.push(AttackScenario {
                    title,
                    narrative,
                    affected_assets: Vec::new(), // Could be enhanced to extract from context
                    related_vulnerabilities: Vec::new(),
                    mitre_techniques: Vec::new(),
                    impact,
                    blocking_points,
                });
            }
        }

        // If parsing failed, create a generic scenario
        if scenarios.is_empty() && !response.trim().is_empty() {
            // Try to extract any useful content
            let lines: Vec<&str> = response.lines().filter(|l| !l.trim().is_empty()).collect();
            if !lines.is_empty() {
                scenarios.push(AttackScenario {
                    title: "Potential Attack Scenario".to_string(),
                    narrative: lines.join(" "),
                    affected_assets: Vec::new(),
                    related_vulnerabilities: Vec::new(),
                    mitre_techniques: Vec::new(),
                    impact: "See narrative for details".to_string(),
                    blocking_points: Vec::new(),
                });
            }
        }

        scenarios
    }

    /// Calculate confidence score based on generated content
    fn calculate_confidence(&self, narrative: &AINarrative) -> u8 {
        let mut score = 0u8;

        if narrative.executive_summary.is_some() {
            score += 20;
        }
        if narrative.technical_summary.is_some() {
            score += 20;
        }
        if narrative.business_impact.is_some() {
            score += 15;
        }
        if !narrative.risk_insights.is_empty() {
            score += 15;
        }
        if narrative.remediation_rationale.is_some() {
            score += 15;
        }
        if !narrative.attack_scenarios.is_empty() {
            score += 10;
        }
        if narrative.compliance_implications.is_some() {
            score += 5;
        }

        score
    }

    /// Generate a fallback narrative when LLM is unavailable
    fn generate_fallback_narrative(&self, report_data: &ReportData) -> AINarrative {
        let summary = &report_data.summary;

        let executive_summary = format!(
            "This security assessment identified {} vulnerabilities across {} systems, \
            including {} critical and {} high severity findings that require immediate attention. \
            The overall risk level is {} (score: {}). \
            The organization should prioritize remediation of critical vulnerabilities to reduce \
            the risk of security incidents and potential data breaches.",
            summary.total_vulnerabilities,
            summary.total_hosts,
            summary.critical_count,
            summary.high_count,
            summary.overall_risk_level,
            summary.overall_risk_score
        );

        let technical_summary = format!(
            "The assessment scanned {} hosts ({} live) and identified {} open ports. \
            A total of {} vulnerabilities were discovered: {} critical, {} high, \
            {} medium, and {} low severity. The overall risk score is {} ({}).",
            summary.total_hosts,
            summary.live_hosts,
            summary.open_ports,
            summary.total_vulnerabilities,
            summary.critical_count,
            summary.high_count,
            summary.medium_count,
            summary.low_count,
            summary.overall_risk_score,
            summary.overall_risk_level
        );

        AINarrative {
            executive_summary: Some(executive_summary),
            technical_summary: Some(technical_summary),
            business_impact: None,
            risk_insights: vec![
                "Multiple systems have critical vulnerabilities requiring immediate remediation".to_string(),
                "Comprehensive patch management process should be reviewed".to_string(),
            ],
            remediation_rationale: None,
            attack_scenarios: Vec::new(),
            compliance_implications: None,
            confidence_score: 30, // Low confidence for fallback
            generated_at: chrono::Utc::now(),
        }
    }
}

/// Convert severity to display string
fn severity_to_string(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let options = NarrativeOptions::default();
        assert_eq!(options.audience, AudienceType::Executive);
        assert!(options.include_attack_scenarios);
        assert!(options.include_compliance);
    }

    #[test]
    fn test_confidence_calculation() {
        let generator = NarrativeGenerator::default_generator();

        let empty_narrative = AINarrative::default();
        assert_eq!(generator.calculate_confidence(&empty_narrative), 0);

        let partial_narrative = AINarrative {
            executive_summary: Some("test".to_string()),
            technical_summary: Some("test".to_string()),
            ..Default::default()
        };
        assert_eq!(generator.calculate_confidence(&partial_narrative), 40);
    }
}
