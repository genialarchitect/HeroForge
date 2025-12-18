//! HIPAA Compliance Report Formatter
//!
//! This module provides HIPAA Security Rule specific formatting for compliance reports,
//! including safeguard breakdowns, risk analysis guidance, and breach notification information.

use crate::compliance::types::FrameworkSummary;
use super::common::{get_score_class, html_escape, generate_compliance_chart, generate_category_breakdown, FrameworkFormatter};

/// HIPAA Security Rule compliance report formatter
pub struct HipaaFormatter;

impl FrameworkFormatter for HipaaFormatter {
    fn framework_name(&self) -> &'static str {
        "HIPAA Security Rule"
    }

    fn framework_id(&self) -> &'static str {
        "hipaa"
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="hipaa">
    <h3>HIPAA Security Rule Compliance Assessment</h3>
    <p class="framework-description">The HIPAA Security Rule establishes national standards to protect
    electronic protected health information (ePHI) through administrative, physical, and technical safeguards.</p>
"#
        ));

        // Score summary
        let score_class = get_score_class(summary.compliance_score);
        html.push_str(&format!(
            r#"    <div class="score-summary">
        <div class="score-badge score-{}">
            <span class="score-value">{:.1}%</span>
            <span class="score-label">Compliance Score</span>
        </div>
        <div class="score-details">
            <p><strong>Total Standards:</strong> {}</p>
            <p><strong>Compliant:</strong> {} | <strong>Partial:</strong> {} | <strong>Non-Compliant:</strong> {}</p>
            <p><strong>Risk Findings:</strong> {}</p>
        </div>
    </div>
"#,
            score_class,
            summary.compliance_score,
            summary.compliant + summary.partially_compliant + summary.non_compliant + summary.not_applicable,
            summary.compliant,
            summary.partially_compliant,
            summary.non_compliant,
            summary.non_compliant
        ));

        // Compliance chart
        html.push_str("    <h4>Safeguard Implementation Status</h4>\n");
        html.push_str(&generate_compliance_chart(summary));

        // Safeguards breakdown
        html.push_str(&self.generate_safeguards_breakdown(summary));

        // Category breakdown
        html.push_str("    <h4>Implementation Specification Analysis</h4>\n");
        html.push_str(&generate_category_breakdown(&summary.by_category));

        // Risk analysis guidance
        html.push_str(&self.generate_risk_analysis_guidance(summary));

        // Breach notification info
        html.push_str(&self.generate_breach_notification_info(summary));

        // Recommendations
        if include_evidence {
            html.push_str(&self.generate_recommendations(summary));
        }

        html.push_str("</div>\n");
        html
    }

    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String {
        let mut recommendations = Vec::new();

        // Analyze safeguard categories
        for cat in &summary.by_category {
            if cat.non_compliant > 0 {
                let safeguard_type = if cat.category.contains("Administrative") {
                    "Administrative"
                } else if cat.category.contains("Physical") {
                    "Physical"
                } else if cat.category.contains("Technical") {
                    "Technical"
                } else {
                    "General"
                };

                recommendations.push(HipaaRecommendation {
                    priority: if cat.percentage < 50.0 { "High" } else { "Medium" },
                    safeguard: safeguard_type.to_string(),
                    category: cat.category.clone(),
                    recommendation: format!(
                        "Address {} non-compliant implementation specifications in {} safeguards",
                        cat.non_compliant, safeguard_type.to_lowercase()
                    ),
                });
            }
        }

        // Generate HTML
        let mut html = String::from("    <h4>Compliance Remediation Priorities</h4>\n    <ul class=\"recommendations-list\">\n");

        for rec in &recommendations {
            html.push_str(&format!(
                r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{} Safeguards - {}:</strong> {}
        </li>
"#,
                rec.priority.to_lowercase(),
                rec.priority,
                html_escape(&rec.safeguard),
                html_escape(&rec.category),
                html_escape(&rec.recommendation)
            ));
        }

        if recommendations.is_empty() {
            html.push_str("        <li>All assessed safeguards are compliant. Continue maintaining current controls and documentation.</li>\n");
        }

        // Add general HIPAA recommendations
        html.push_str(r#"        <li>
            <span class="priority-low">[Ongoing]</span>
            <strong>Documentation:</strong> Ensure all policies, procedures, and risk assessments are documented and reviewed annually.
        </li>
        <li>
            <span class="priority-low">[Ongoing]</span>
            <strong>Training:</strong> Maintain workforce training records and conduct regular security awareness training.
        </li>
"#);

        html.push_str("    </ul>\n");
        html
    }
}

impl HipaaFormatter {
    /// Generate HIPAA safeguards breakdown (Administrative, Physical, Technical)
    fn generate_safeguards_breakdown(&self, summary: &FrameworkSummary) -> String {
        let safeguards = get_safeguard_standards();

        let mut html = String::from("    <h4>Safeguards Status</h4>\n    <div class=\"framework-grid\">\n");

        for (safeguard_type, standards) in &safeguards {
            // Calculate aggregate score for this safeguard type
            let matching_cats: Vec<_> = summary.by_category.iter()
                .filter(|c| c.category.contains(safeguard_type))
                .collect();

            let total_score: f32 = matching_cats.iter().map(|c| c.percentage).sum();
            let avg_score = if matching_cats.is_empty() { 0.0 } else { total_score / matching_cats.len() as f32 };
            let score_class = get_score_class(avg_score);

            let total_compliant: usize = matching_cats.iter().map(|c| c.compliant).sum();
            let total_total: usize = matching_cats.iter().map(|c| c.total).sum();
            let total_non_compliant: usize = matching_cats.iter().map(|c| c.non_compliant).sum();
            // Calculate partial as the difference (no explicit partial field in CategorySummary)
            let total_partial: usize = total_total.saturating_sub(total_compliant + total_non_compliant);

            html.push_str(&format!(
                r#"        <div class="framework-card">
            <h4>{} Safeguards</h4>
            <div class="score score-{}">{:.1}%</div>
            <div class="framework-stats">
                <span class="stat compliant">{} compliant</span>
                <span class="stat partial">{} partial</span>
                <span class="stat non-compliant">{} non-compliant</span>
            </div>
            <p class="standards-count">{} implementation specifications</p>
        </div>
"#,
                safeguard_type,
                score_class,
                avg_score,
                total_compliant,
                total_partial,
                total_non_compliant,
                standards.len()
            ));
        }

        html.push_str("    </div>\n");

        // Detailed standards table
        html.push_str("    <h4>Implementation Standards Details</h4>\n    <table class=\"control-table\">\n");
        html.push_str("        <tr><th>Safeguard</th><th>Standard</th><th>Description</th><th>Type</th></tr>\n");

        for (safeguard_type, standards) in &safeguards {
            for (std_id, std_name, req_type) in standards {
                html.push_str(&format!(
                    "        <tr><td>{}</td><td>{}</td><td>{}</td><td><span class=\"requirement-{}\">{}</span></td></tr>\n",
                    safeguard_type,
                    std_id,
                    html_escape(std_name),
                    req_type.to_lowercase(),
                    req_type
                ));
            }
        }

        html.push_str("    </table>\n");
        html
    }

    /// Generate risk analysis guidance section
    fn generate_risk_analysis_guidance(&self, summary: &FrameworkSummary) -> String {
        let risk_level = if summary.compliance_score >= 85.0 {
            ("Low", "Your organization demonstrates strong ePHI protection controls. Continue regular risk assessments to maintain compliance.")
        } else if summary.compliance_score >= 65.0 {
            ("Moderate", "Several areas require attention to reduce risk to ePHI. Prioritize addressing non-compliant technical and administrative safeguards.")
        } else {
            ("High", "Significant gaps in ePHI protection require immediate attention. Conduct a comprehensive risk analysis and implement corrective actions.")
        };

        format!(
            r#"    <div class="risk-analysis">
        <h4>Risk Analysis Summary</h4>
        <div class="risk-card risk-{}">
            <strong>Overall Risk Level: {}</strong>
            <p>{}</p>
        </div>
        <h5>Risk Analysis Requirements (164.308(a)(1)(ii)(A))</h5>
        <ul>
            <li>Conduct accurate and thorough assessment of potential risks and vulnerabilities to ePHI</li>
            <li>Document the risk analysis process and findings</li>
            <li>Implement security measures to reduce risks to reasonable and appropriate levels</li>
            <li>Review and update risk analysis regularly and when operational changes occur</li>
        </ul>
    </div>
"#,
            risk_level.0.to_lowercase(),
            risk_level.0,
            risk_level.1
        )
    }

    /// Generate breach notification information
    fn generate_breach_notification_info(&self, summary: &FrameworkSummary) -> String {
        let breach_risk = if summary.compliance_score < 60.0 {
            "elevated"
        } else if summary.compliance_score < 80.0 {
            "moderate"
        } else {
            "low"
        };

        format!(
            r#"    <div class="breach-info">
        <h4>Breach Notification Rule Considerations</h4>
        <p class="breach-risk breach-risk-{}">Based on current compliance posture, breach risk is assessed as <strong>{}</strong>.</p>
        <h5>Breach Notification Requirements (45 CFR 164.400-414)</h5>
        <ul>
            <li><strong>Individual Notice:</strong> Notify affected individuals within 60 days of discovery</li>
            <li><strong>Media Notice:</strong> If breach affects 500+ residents of a state, notify prominent media outlets</li>
            <li><strong>HHS Notice:</strong> Report breaches affecting 500+ individuals immediately; smaller breaches annually</li>
            <li><strong>Business Associate:</strong> Must notify covered entity within 60 days of discovering breach</li>
        </ul>
        <p class="note">Maintain breach response procedures and documentation as part of your security program.</p>
    </div>
"#,
            breach_risk,
            breach_risk
        )
    }
}

/// HIPAA-specific recommendation structure
struct HipaaRecommendation {
    priority: &'static str,
    safeguard: String,
    category: String,
    recommendation: String,
}

/// Get HIPAA safeguard standards organized by type
fn get_safeguard_standards() -> Vec<(&'static str, Vec<(&'static str, &'static str, &'static str)>)> {
    vec![
        ("Administrative", vec![
            ("164.308(a)(1)", "Security Management Process", "Required"),
            ("164.308(a)(2)", "Assigned Security Responsibility", "Required"),
            ("164.308(a)(3)", "Workforce Security", "Addressable"),
            ("164.308(a)(4)", "Information Access Management", "Required"),
            ("164.308(a)(5)", "Security Awareness and Training", "Addressable"),
            ("164.308(a)(6)", "Security Incident Procedures", "Required"),
            ("164.308(a)(7)", "Contingency Plan", "Required"),
            ("164.308(a)(8)", "Evaluation", "Required"),
            ("164.308(b)(1)", "Business Associate Contracts", "Required"),
        ]),
        ("Physical", vec![
            ("164.310(a)(1)", "Facility Access Controls", "Addressable"),
            ("164.310(b)", "Workstation Use", "Required"),
            ("164.310(c)", "Workstation Security", "Required"),
            ("164.310(d)(1)", "Device and Media Controls", "Required"),
        ]),
        ("Technical", vec![
            ("164.312(a)(1)", "Access Control", "Required"),
            ("164.312(b)", "Audit Controls", "Required"),
            ("164.312(c)(1)", "Integrity", "Addressable"),
            ("164.312(d)", "Person or Entity Authentication", "Required"),
            ("164.312(e)(1)", "Transmission Security", "Addressable"),
        ]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::types::{CategorySummary, ComplianceFramework};

    fn create_test_summary() -> FrameworkSummary {
        FrameworkSummary {
            framework: ComplianceFramework::Hipaa,
            total_controls: 30,
            compliant: 20,
            non_compliant: 3,
            partially_compliant: 5,
            not_applicable: 2,
            not_assessed: 0,
            manual_overrides: 0,
            compliance_score: 78.0,
            by_category: vec![
                CategorySummary {
                    category: "Administrative Safeguards".to_string(),
                    total: 9,
                    compliant: 8,
                    non_compliant: 1,
                    percentage: 85.0,
                },
                CategorySummary {
                    category: "Technical Safeguards".to_string(),
                    total: 8,
                    compliant: 4,
                    non_compliant: 4,
                    percentage: 70.0,
                },
                CategorySummary {
                    category: "Physical Safeguards".to_string(),
                    total: 4,
                    compliant: 3,
                    non_compliant: 1,
                    percentage: 80.0,
                },
            ],
        }
    }

    #[test]
    fn test_hipaa_formatter_basics() {
        let formatter = HipaaFormatter;
        assert_eq!(formatter.framework_name(), "HIPAA Security Rule");
        assert_eq!(formatter.framework_id(), "hipaa");
    }

    #[test]
    fn test_generate_section() {
        let formatter = HipaaFormatter;
        let summary = create_test_summary();
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("HIPAA Security Rule Compliance Assessment"));
        assert!(html.contains("Safeguards Status"));
        assert!(html.contains("Risk Analysis Summary"));
        assert!(html.contains("Breach Notification Rule"));
    }
}
