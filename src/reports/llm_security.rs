//! LLM Security Assessment Report Generator
//!
//! Generates professional PDF, HTML, and Markdown reports for LLM security test results.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ai_security::types::{
    AgentTestResult, ConversationTestResult, LLMReportFormat, LLMSecurityTest,
    LLMTestCategory, LLMTestResult, LLMTestSummary, ModelFingerprint, Remediation,
    TestCaseSeverity,
};
use crate::ai_security::llm_testing::remediation::{get_llm_remediation, get_agent_remediation};

/// LLM Security Assessment Report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMSecurityReport {
    pub id: String,
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub target_name: String,
    pub target_endpoint: String,

    // Executive Summary
    pub executive_summary: ExecutiveSummary,

    // Test Results
    pub single_turn_results: Vec<LLMTestResult>,
    pub conversation_results: Vec<ConversationTestResult>,
    pub agent_results: Vec<AgentTestResult>,

    // Summaries
    pub test_summary: LLMTestSummary,

    // Model Fingerprint
    pub fingerprint: Option<ModelFingerprint>,

    // Remediation
    pub remediations: Vec<Remediation>,

    // Metadata
    pub test_duration_ms: u64,
    pub customer_name: Option<String>,
    pub engagement_id: Option<String>,
}

/// Executive summary for the report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overall_risk_level: RiskLevel,
    pub overall_risk_score: f64,
    pub total_tests_run: i64,
    pub vulnerabilities_found: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub key_findings: Vec<String>,
    pub top_recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "Critical"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Minimal => write!(f, "Minimal"),
        }
    }
}

/// Report generator for LLM security assessments
pub struct LLMReportGenerator;

impl LLMReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a complete LLM security report
    pub fn generate_report(
        &self,
        test: &LLMSecurityTest,
        single_turn_results: Vec<LLMTestResult>,
        conversation_results: Vec<ConversationTestResult>,
        agent_results: Vec<AgentTestResult>,
        fingerprint: Option<ModelFingerprint>,
        customer_name: Option<String>,
    ) -> LLMSecurityReport {
        // Calculate summary
        let test_summary = self.calculate_summary(
            &single_turn_results,
            &conversation_results,
            &agent_results,
        );

        // Generate executive summary
        let executive_summary = self.generate_executive_summary(
            &test_summary,
            &single_turn_results,
            &conversation_results,
            &agent_results,
        );

        // Collect remediations
        let remediations = self.collect_remediations(
            &single_turn_results,
            &conversation_results,
            &agent_results,
        );

        LLMSecurityReport {
            id: uuid::Uuid::new_v4().to_string(),
            title: format!("LLM Security Assessment - {}", test.target_name),
            generated_at: Utc::now(),
            target_name: test.target_name.clone(),
            target_endpoint: test.target_config.as_ref()
                .map(|c| c.endpoint.clone())
                .unwrap_or_default(),
            executive_summary,
            single_turn_results,
            conversation_results,
            agent_results,
            test_summary,
            fingerprint,
            remediations,
            test_duration_ms: 0, // Would be calculated from test times
            customer_name,
            engagement_id: test.engagement_id.clone(),
        }
    }

    /// Calculate test summary from all results
    fn calculate_summary(
        &self,
        single_turn: &[LLMTestResult],
        conversation: &[ConversationTestResult],
        agent: &[AgentTestResult],
    ) -> LLMTestSummary {
        let mut total = 0i64;
        let mut failed = 0i64;
        let mut by_category: HashMap<String, i64> = HashMap::new();
        let mut by_severity: HashMap<String, i64> = HashMap::new();

        // Process single-turn results
        for result in single_turn {
            total += 1;
            if result.vulnerable {
                failed += 1;
                *by_category.entry(result.category.to_string()).or_insert(0) += 1;
                *by_severity.entry(result.severity.to_string()).or_insert(0) += 1;
            }
        }

        // Process conversation results
        for result in conversation {
            total += 1;
            if result.final_status == crate::ai_security::types::ConversationTestStatus::Passed {
                failed += 1;
                *by_category.entry(result.category.to_string()).or_insert(0) += 1;
                *by_severity.entry(result.severity.to_string()).or_insert(0) += 1;
            }
        }

        // Process agent results
        for result in agent {
            total += 1;
            if result.vulnerable {
                failed += 1;
                *by_category.entry(result.category.to_string()).or_insert(0) += 1;
                *by_severity.entry(result.severity.to_string()).or_insert(0) += 1;
            }
        }

        // Calculate risk score
        let risk_score = self.calculate_risk_score(&by_severity, total);

        LLMTestSummary {
            total_tests: total,
            passed: total - failed,
            failed,
            vulnerabilities_by_category: by_category,
            vulnerabilities_by_severity: by_severity,
            overall_risk_score: risk_score,
        }
    }

    /// Calculate overall risk score
    fn calculate_risk_score(&self, by_severity: &HashMap<String, i64>, total: i64) -> f64 {
        if total == 0 {
            return 0.0;
        }

        let critical = *by_severity.get("critical").unwrap_or(&0) as f64;
        let high = *by_severity.get("high").unwrap_or(&0) as f64;
        let medium = *by_severity.get("medium").unwrap_or(&0) as f64;
        let low = *by_severity.get("low").unwrap_or(&0) as f64;

        // Weighted score calculation
        let score = (critical * 40.0 + high * 25.0 + medium * 15.0 + low * 5.0) / total as f64;

        score.min(100.0)
    }

    /// Generate executive summary
    fn generate_executive_summary(
        &self,
        summary: &LLMTestSummary,
        single_turn: &[LLMTestResult],
        conversation: &[ConversationTestResult],
        agent: &[AgentTestResult],
    ) -> ExecutiveSummary {
        let critical = *summary.vulnerabilities_by_severity.get("critical").unwrap_or(&0);
        let high = *summary.vulnerabilities_by_severity.get("high").unwrap_or(&0);
        let medium = *summary.vulnerabilities_by_severity.get("medium").unwrap_or(&0);
        let low = *summary.vulnerabilities_by_severity.get("low").unwrap_or(&0);

        // Determine overall risk level
        let risk_level = if critical > 0 {
            RiskLevel::Critical
        } else if high > 2 {
            RiskLevel::High
        } else if high > 0 || medium > 3 {
            RiskLevel::Medium
        } else if medium > 0 || low > 5 {
            RiskLevel::Low
        } else {
            RiskLevel::Minimal
        };

        // Generate key findings
        let mut key_findings = Vec::new();

        if critical > 0 {
            key_findings.push(format!(
                "{} critical vulnerabilities require immediate attention",
                critical
            ));
        }

        // Find most common vulnerability category
        if let Some((category, count)) = summary.vulnerabilities_by_category.iter()
            .max_by_key(|(_, v)| *v)
        {
            key_findings.push(format!(
                "Most common vulnerability: {} ({} instances)",
                category, count
            ));
        }

        // Check for conversation-based vulnerabilities
        let conv_vulns: Vec<_> = conversation.iter()
            .filter(|c| c.final_status == crate::ai_security::types::ConversationTestStatus::Passed)
            .collect();
        if !conv_vulns.is_empty() {
            key_findings.push(format!(
                "{} multi-turn conversation attacks succeeded",
                conv_vulns.len()
            ));
        }

        // Check for agent vulnerabilities
        let agent_vulns: Vec<_> = agent.iter().filter(|a| a.vulnerable).collect();
        if !agent_vulns.is_empty() {
            key_findings.push(format!(
                "{} agent/tool exploitation attempts succeeded",
                agent_vulns.len()
            ));
        }

        // Generate top recommendations
        let mut recommendations = Vec::new();

        if summary.vulnerabilities_by_category.contains_key("prompt_injection") {
            recommendations.push("Implement input validation and delimiter tokens for prompt injection defense".to_string());
        }

        if summary.vulnerabilities_by_category.contains_key("jailbreak") {
            recommendations.push("Strengthen safety fine-tuning and add multi-layer content filtering".to_string());
        }

        if summary.vulnerabilities_by_category.contains_key("data_extraction") {
            recommendations.push("Remove sensitive data from system prompts and implement output filtering".to_string());
        }

        if !agent_vulns.is_empty() {
            recommendations.push("Implement strict input validation for all tool parameters".to_string());
        }

        if recommendations.is_empty() {
            recommendations.push("Continue monitoring for new attack patterns".to_string());
        }

        ExecutiveSummary {
            overall_risk_level: risk_level,
            overall_risk_score: summary.overall_risk_score,
            total_tests_run: summary.total_tests,
            vulnerabilities_found: summary.failed,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            key_findings,
            top_recommendations: recommendations,
        }
    }

    /// Collect all applicable remediations
    fn collect_remediations(
        &self,
        single_turn: &[LLMTestResult],
        conversation: &[ConversationTestResult],
        agent: &[AgentTestResult],
    ) -> Vec<Remediation> {
        let mut seen_categories: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut remediations = Vec::new();

        // Collect from single-turn results
        for result in single_turn.iter().filter(|r| r.vulnerable) {
            let key = format!("llm_{}", result.category);
            if !seen_categories.contains(&key) {
                seen_categories.insert(key);
                remediations.push(get_llm_remediation(&result.category, &result.severity));
            }
        }

        // Collect from conversation results
        for result in conversation.iter().filter(|r|
            r.final_status == crate::ai_security::types::ConversationTestStatus::Passed
        ) {
            let key = format!("conv_{}", result.category);
            if !seen_categories.contains(&key) {
                seen_categories.insert(key);
                remediations.push(get_llm_remediation(&result.category, &result.severity));
            }
        }

        // Collect from agent results
        for result in agent.iter().filter(|r| r.vulnerable) {
            let key = format!("agent_{}", result.category);
            if !seen_categories.contains(&key) {
                seen_categories.insert(key);
                remediations.push(get_agent_remediation(&result.category, &result.severity));
            }
        }

        // Sort by priority
        remediations.sort_by_key(|r| r.priority);

        remediations
    }

    /// Generate report in specified format
    pub fn generate_formatted(
        &self,
        report: &LLMSecurityReport,
        format: LLMReportFormat,
    ) -> Result<String> {
        match format {
            LLMReportFormat::Markdown => self.generate_markdown(report),
            LLMReportFormat::Html => self.generate_html(report),
            LLMReportFormat::Json => Ok(serde_json::to_string_pretty(report)?),
            LLMReportFormat::Pdf => {
                // Generate HTML first, then convert to PDF
                // For now, return HTML that can be converted
                self.generate_html(report)
            }
        }
    }

    /// Generate Markdown report
    fn generate_markdown(&self, report: &LLMSecurityReport) -> Result<String> {
        let mut md = String::new();

        // Title and header
        md.push_str(&format!("# {}\n\n", report.title));
        md.push_str(&format!("**Generated:** {}\n\n", report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        md.push_str(&format!("**Target:** {}\n\n", report.target_name));

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!("### Overall Risk Level: **{}**\n\n", report.executive_summary.overall_risk_level));
        md.push_str(&format!("- **Risk Score:** {:.1}/100\n", report.executive_summary.overall_risk_score));
        md.push_str(&format!("- **Total Tests:** {}\n", report.executive_summary.total_tests_run));
        md.push_str(&format!("- **Vulnerabilities Found:** {}\n", report.executive_summary.vulnerabilities_found));
        md.push_str(&format!("  - Critical: {}\n", report.executive_summary.critical_count));
        md.push_str(&format!("  - High: {}\n", report.executive_summary.high_count));
        md.push_str(&format!("  - Medium: {}\n", report.executive_summary.medium_count));
        md.push_str(&format!("  - Low: {}\n\n", report.executive_summary.low_count));

        // Key Findings
        md.push_str("### Key Findings\n\n");
        for finding in &report.executive_summary.key_findings {
            md.push_str(&format!("- {}\n", finding));
        }
        md.push_str("\n");

        // Top Recommendations
        md.push_str("### Top Recommendations\n\n");
        for (i, rec) in report.executive_summary.top_recommendations.iter().enumerate() {
            md.push_str(&format!("{}. {}\n", i + 1, rec));
        }
        md.push_str("\n");

        // Model Fingerprint
        if let Some(ref fp) = report.fingerprint {
            md.push_str("## Model Identification\n\n");
            md.push_str(&format!("- **Likely Model Family:** {}\n", fp.likely_model_family));
            if let Some(ref version) = fp.likely_model_version {
                md.push_str(&format!("- **Likely Version:** {}\n", version));
            }
            md.push_str(&format!("- **Confidence:** {:.0}%\n", fp.confidence * 100.0));
            if let Some(ctx) = fp.estimated_context_window {
                md.push_str(&format!("- **Estimated Context Window:** {} tokens\n", ctx));
            }
            md.push_str("\n");

            if !fp.safety_mechanisms.is_empty() {
                md.push_str("### Detected Safety Mechanisms\n\n");
                for mech in &fp.safety_mechanisms {
                    md.push_str(&format!("- **{}** ({}): {}\n",
                        mech.mechanism_type,
                        mech.strength,
                        mech.description
                    ));
                }
                md.push_str("\n");
            }

            if !fp.known_vulnerabilities.is_empty() {
                md.push_str("### Known Vulnerabilities for This Model Family\n\n");
                for vuln in &fp.known_vulnerabilities {
                    md.push_str(&format!("- {}\n", vuln));
                }
                md.push_str("\n");
            }
        }

        // Test Results Summary
        md.push_str("## Test Results Summary\n\n");

        // By Category
        md.push_str("### Vulnerabilities by Category\n\n");
        md.push_str("| Category | Count |\n|----------|-------|\n");
        for (category, count) in &report.test_summary.vulnerabilities_by_category {
            md.push_str(&format!("| {} | {} |\n", category, count));
        }
        md.push_str("\n");

        // Single-Turn Vulnerabilities
        let vulns: Vec<_> = report.single_turn_results.iter()
            .filter(|r| r.vulnerable)
            .collect();
        if !vulns.is_empty() {
            md.push_str("## Single-Turn Test Vulnerabilities\n\n");
            for result in vulns {
                md.push_str(&format!("### {}\n\n", result.test_case_name));
                md.push_str(&format!("- **Category:** {}\n", result.category));
                md.push_str(&format!("- **Severity:** {}\n", result.severity));
                md.push_str(&format!("- **Confidence:** {:.0}%\n", result.confidence * 100.0));
                if let Some(ref cwe) = result.cwe_id {
                    md.push_str(&format!("- **CWE:** {}\n", cwe));
                }
                md.push_str("\n**Indicators:**\n");
                for indicator in &result.indicators {
                    md.push_str(&format!("- {}\n", indicator));
                }
                md.push_str("\n");
            }
        }

        // Conversation Test Vulnerabilities
        let conv_vulns: Vec<_> = report.conversation_results.iter()
            .filter(|r| r.final_status == crate::ai_security::types::ConversationTestStatus::Passed)
            .collect();
        if !conv_vulns.is_empty() {
            md.push_str("## Multi-Turn Conversation Vulnerabilities\n\n");
            for result in conv_vulns {
                md.push_str(&format!("### {}\n\n", result.test_name));
                md.push_str(&format!("- **Category:** {}\n", result.category));
                md.push_str(&format!("- **Severity:** {}\n", result.severity));
                if let Some(turn) = result.vulnerability_detected_at_turn {
                    md.push_str(&format!("- **Vulnerability detected at turn:** {}\n", turn + 1));
                }
                md.push_str(&format!("- **Confidence:** {:.0}%\n", result.overall_confidence * 100.0));
                md.push_str("\n");
            }
        }

        // Agent Test Vulnerabilities
        let agent_vulns: Vec<_> = report.agent_results.iter()
            .filter(|r| r.vulnerable)
            .collect();
        if !agent_vulns.is_empty() {
            md.push_str("## Agent/Tool Exploitation Vulnerabilities\n\n");
            for result in agent_vulns {
                md.push_str(&format!("### {}\n\n", result.test_case_name));
                md.push_str(&format!("- **Category:** {}\n", result.category));
                md.push_str(&format!("- **Severity:** {}\n", result.severity));
                md.push_str(&format!("- **Confidence:** {:.0}%\n", result.confidence * 100.0));
                if let Some(ref cwe) = result.cwe_id {
                    md.push_str(&format!("- **CWE:** {}\n", cwe));
                }
                if !result.tool_calls.is_empty() {
                    md.push_str("\n**Detected Tool Calls:**\n");
                    for tc in &result.tool_calls {
                        md.push_str(&format!("- `{}`", tc.tool_name));
                        if tc.is_malicious {
                            md.push_str(" ⚠️ MALICIOUS");
                        }
                        md.push_str("\n");
                    }
                }
                md.push_str("\n");
            }
        }

        // Remediation Guidance
        if !report.remediations.is_empty() {
            md.push_str("## Remediation Guidance\n\n");
            for rem in &report.remediations {
                md.push_str(&format!("### {} (Priority {})\n\n", rem.category, rem.priority));
                md.push_str(&format!("**Severity:** {} | **Effort:** {}\n\n", rem.severity, rem.effort_estimate));
                md.push_str(&format!("**Description:** {}\n\n", rem.vulnerability_description));
                md.push_str(&format!("**Impact:** {}\n\n", rem.impact));
                md.push_str("**Remediation Steps:**\n");
                for (i, step) in rem.remediation_steps.iter().enumerate() {
                    md.push_str(&format!("{}. {}\n", i + 1, step));
                }
                if let Some(ref owasp) = rem.owasp_llm_mapping {
                    md.push_str(&format!("\n**OWASP LLM Mapping:** {}\n", owasp));
                }
                if let Some(ref cwe) = rem.cwe_mapping {
                    md.push_str(&format!("**CWE Mapping:** {}\n", cwe));
                }
                md.push_str("\n---\n\n");
            }
        }

        Ok(md)
    }

    /// Generate HTML report
    fn generate_html(&self, report: &LLMSecurityReport) -> Result<String> {
        let risk_color = match report.executive_summary.overall_risk_level {
            RiskLevel::Critical => "#dc3545",
            RiskLevel::High => "#fd7e14",
            RiskLevel::Medium => "#ffc107",
            RiskLevel::Low => "#28a745",
            RiskLevel::Minimal => "#17a2b8",
        };

        let mut html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .risk-badge {{ display: inline-block; padding: 8px 16px; border-radius: 4px; color: white; font-weight: bold; background-color: {}; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card.critical {{ background: #f8d7da; border: 1px solid #f5c6cb; }}
        .summary-card.high {{ background: #fff3cd; border: 1px solid #ffeeba; }}
        .summary-card.medium {{ background: #d1ecf1; border: 1px solid #bee5eb; }}
        .summary-card.low {{ background: #d4edda; border: 1px solid #c3e6cb; }}
        .summary-card h3 {{ margin: 0; font-size: 2em; }}
        .summary-card p {{ margin: 5px 0 0 0; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; }}
        .section {{ margin: 40px 0; }}
        .finding {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #007bff; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .severity {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; }}
        .severity.critical {{ background: #dc3545; color: white; }}
        .severity.high {{ background: #fd7e14; color: white; }}
        .severity.medium {{ background: #ffc107; color: black; }}
        .severity.low {{ background: #28a745; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{}</h1>
        <p><strong>Generated:</strong> {}</p>
        <p><strong>Target:</strong> {}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>Overall Risk Level: <span class="risk-badge">{}</span></p>
        <p>Risk Score: <strong>{:.1}/100</strong></p>

        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>{}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{}</h3>
                <p>Low</p>
            </div>
        </div>

        <h3>Key Findings</h3>
        <ul>
"#,
            report.title,
            risk_color,
            report.title,
            report.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.target_name,
            report.executive_summary.overall_risk_level,
            report.executive_summary.overall_risk_score,
            report.executive_summary.critical_count,
            report.executive_summary.high_count,
            report.executive_summary.medium_count,
            report.executive_summary.low_count,
        );

        for finding in &report.executive_summary.key_findings {
            html.push_str(&format!("            <li>{}</li>\n", finding));
        }

        html.push_str(r#"        </ul>

        <h3>Top Recommendations</h3>
        <ol>
"#);

        for rec in &report.executive_summary.top_recommendations {
            html.push_str(&format!("            <li>{}</li>\n", rec));
        }

        html.push_str(r#"        </ol>
    </div>
"#);

        // Add vulnerabilities section
        let vulns: Vec<_> = report.single_turn_results.iter()
            .filter(|r| r.vulnerable)
            .collect();

        if !vulns.is_empty() {
            html.push_str(r#"
    <div class="section">
        <h2>Vulnerability Details</h2>
"#);
            for result in vulns {
                let severity_class = result.severity.to_string().to_lowercase();
                html.push_str(&format!(r#"
        <div class="finding {}">
            <h4>{}</h4>
            <p><span class="severity {}">{}:</span> {} | Confidence: {:.0}%</p>
            <p><strong>Indicators:</strong></p>
            <ul>
"#,
                    severity_class,
                    result.test_case_name,
                    severity_class,
                    result.severity,
                    result.category,
                    result.confidence * 100.0,
                ));
                for indicator in &result.indicators {
                    html.push_str(&format!("                <li>{}</li>\n", indicator));
                }
                html.push_str("            </ul>\n        </div>\n");
            }
            html.push_str("    </div>\n");
        }

        html.push_str(r#"
</body>
</html>"#);

        Ok(html)
    }
}

impl Default for LLMReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_determination() {
        assert_eq!(RiskLevel::Critical.to_string(), "Critical");
    }

    #[test]
    fn test_calculate_risk_score() {
        let generator = LLMReportGenerator::new();
        let mut by_severity = HashMap::new();
        by_severity.insert("critical".to_string(), 1);
        by_severity.insert("high".to_string(), 2);

        let score = generator.calculate_risk_score(&by_severity, 10);
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }
}
