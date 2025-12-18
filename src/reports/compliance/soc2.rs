//! SOC 2 Compliance Report Formatter
//!
//! This module provides SOC 2 Type II specific formatting for compliance reports,
//! including Trust Services Criteria breakdowns, common criteria analysis, and audit readiness assessment.

use crate::compliance::types::{ControlStatus, FrameworkSummary};
use super::common::{get_score_class, html_escape, generate_compliance_chart, generate_category_breakdown, FrameworkFormatter};

/// SOC 2 Type II compliance report formatter
pub struct Soc2Formatter;

impl FrameworkFormatter for Soc2Formatter {
    fn framework_name(&self) -> &'static str {
        "SOC 2 Type II"
    }

    fn framework_id(&self) -> &'static str {
        "soc2"
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="soc2">
    <h3>SOC 2 Type II Compliance Assessment</h3>
    <p class="framework-description">SOC 2 reports focus on a service organization's controls relevant to
    security, availability, processing integrity, confidentiality, and privacy as defined by the AICPA's
    Trust Services Criteria.</p>
"#
        ));

        // Score summary
        let score_class = get_score_class(summary.compliance_score);
        html.push_str(&format!(
            r#"    <div class="score-summary">
        <div class="score-badge score-{}">
            <span class="score-value">{:.1}%</span>
            <span class="score-label">Readiness Score</span>
        </div>
        <div class="score-details">
            <p><strong>Total Criteria:</strong> {}</p>
            <p><strong>Met:</strong> {} | <strong>Partial:</strong> {} | <strong>Not Met:</strong> {}</p>
            <p><strong>Exceptions Identified:</strong> {}</p>
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
        html.push_str("    <h4>Trust Services Criteria Coverage</h4>\n");
        html.push_str(&generate_compliance_chart(summary));

        // Trust Services Categories breakdown
        html.push_str(&self.generate_trust_services_breakdown(summary));

        // Common Criteria status
        html.push_str(&self.generate_common_criteria_status(summary));

        // Category breakdown
        html.push_str("    <h4>Criteria Analysis by Category</h4>\n");
        html.push_str(&generate_category_breakdown(&summary.by_category));

        // Audit readiness assessment
        html.push_str(&self.generate_audit_readiness(summary));

        // Recommendations
        if include_evidence {
            html.push_str(&self.generate_recommendations(summary));
        }

        html.push_str("</div>\n");
        html
    }

    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String {
        let mut recommendations = Vec::new();

        // Analyze by Trust Services category
        for cat in &summary.by_category {
            if cat.non_compliant > 0 || 0 > 0 {
                let tsc_category = if cat.category.contains("Security") || cat.category.contains("CC") {
                    "Security (Common Criteria)"
                } else if cat.category.contains("Availability") || cat.category.starts_with("A") {
                    "Availability"
                } else if cat.category.contains("Processing") || cat.category.starts_with("PI") {
                    "Processing Integrity"
                } else if cat.category.contains("Confidentiality") || cat.category.starts_with("C") {
                    "Confidentiality"
                } else if cat.category.contains("Privacy") || cat.category.starts_with("P") {
                    "Privacy"
                } else {
                    "General"
                };

                recommendations.push(Soc2Recommendation {
                    priority: if cat.percentage < 50.0 { "High" } else if cat.percentage < 75.0 { "Medium" } else { "Low" },
                    category: tsc_category.to_string(),
                    criteria: cat.category.clone(),
                    recommendation: format!(
                        "Address {} criteria exceptions to achieve full {} compliance (current: {:.1}%)",
                        cat.non_compliant + 0,
                        tsc_category.to_lowercase(),
                        cat.percentage
                    ),
                });
            }
        }

        // Generate HTML
        let mut html = String::from("    <h4>Audit Preparation Recommendations</h4>\n    <ul class=\"recommendations-list\">\n");

        for rec in &recommendations {
            html.push_str(&format!(
                r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{} - {}:</strong> {}
        </li>
"#,
                rec.priority.to_lowercase(),
                rec.priority,
                html_escape(&rec.category),
                html_escape(&rec.criteria),
                html_escape(&rec.recommendation)
            ));
        }

        if recommendations.is_empty() {
            html.push_str("        <li>All Trust Services Criteria are met. Organization is well-positioned for SOC 2 Type II audit.</li>\n");
        }

        // Add audit preparation tips
        html.push_str(r#"        <li>
            <span class="priority-low">[Documentation]</span>
            <strong>Evidence Preparation:</strong> Ensure all policies, procedures, and control evidence are documented for the observation period.
        </li>
        <li>
            <span class="priority-low">[Continuous Monitoring]</span>
            <strong>Control Testing:</strong> Maintain evidence of control operation over the entire audit period (typically 6-12 months).
        </li>
"#);

        html.push_str("    </ul>\n");
        html
    }
}

impl Soc2Formatter {
    /// Generate Trust Services Categories breakdown
    fn generate_trust_services_breakdown(&self, summary: &FrameworkSummary) -> String {
        let categories = get_trust_services_criteria();

        let mut html = String::from("    <h4>Trust Services Categories</h4>\n    <div class=\"framework-grid\">\n");

        for (cat_id, cat_name, cat_desc, is_common) in &categories {
            // Find matching category in summary
            let cat_info = summary.by_category.iter()
                .find(|c| c.category.starts_with(cat_id) || c.category.contains(cat_name));

            let score = cat_info.map(|c| c.percentage).unwrap_or(0.0);
            let score_class = get_score_class(score);

            let badge = if *is_common { "(Common)" } else { "(Additional)" };

            html.push_str(&format!(
                r#"        <div class="framework-card">
            <h4>{} {} <span class="badge">{}</span></h4>
            <div class="score score-{}">{:.1}%</div>
            <p>{}</p>
        </div>
"#,
                cat_id,
                html_escape(cat_name),
                badge,
                score_class,
                score,
                html_escape(cat_desc)
            ));
        }

        html.push_str("    </div>\n");
        html
    }

    /// Generate Common Criteria (CC) series status
    fn generate_common_criteria_status(&self, summary: &FrameworkSummary) -> String {
        let cc_series = get_common_criteria_series();

        let mut html = String::from("    <h4>Common Criteria (Security) Status</h4>\n    <table class=\"control-table\">\n");
        html.push_str("        <tr><th>Series</th><th>Focus Area</th><th>Status</th><th>Score</th></tr>\n");

        for (series_id, series_name) in &cc_series {
            // Try to find matching category
            let cat_info = summary.by_category.iter()
                .find(|c| c.category.contains(series_id));

            let (status, score) = if let Some(cat) = cat_info {
                let s = if cat.percentage >= 100.0 { ControlStatus::Compliant }
                else if cat.percentage >= 50.0 { ControlStatus::PartiallyCompliant }
                else { ControlStatus::NonCompliant };
                (s, cat.percentage)
            } else {
                (ControlStatus::NotAssessed, 0.0)
            };

            let status_class = match status {
                ControlStatus::Compliant => "status-compliant",
                ControlStatus::PartiallyCompliant => "status-partial",
                ControlStatus::NonCompliant => "status-non-compliant",
                _ => "status-not-assessed",
            };

            let status_text = match status {
                ControlStatus::Compliant => "Met",
                ControlStatus::PartiallyCompliant => "Partial",
                ControlStatus::NonCompliant => "Not Met",
                _ => "Not Assessed",
            };

            html.push_str(&format!(
                "        <tr><td>{}</td><td>{}</td><td><span class=\"status-badge {}\">{}</span></td><td>{:.1}%</td></tr>\n",
                series_id, html_escape(series_name), status_class, status_text, score
            ));
        }

        html.push_str("    </table>\n");
        html
    }

    /// Generate audit readiness assessment
    fn generate_audit_readiness(&self, summary: &FrameworkSummary) -> String {
        let readiness = if summary.compliance_score >= 90.0 {
            ("High", "ready", "Your organization demonstrates strong control implementation and is well-prepared for a SOC 2 Type II audit.")
        } else if summary.compliance_score >= 75.0 {
            ("Moderate", "preparing", "Most controls are in place but some gaps exist. Address identified exceptions before scheduling audit.")
        } else if summary.compliance_score >= 50.0 {
            ("Low", "developing", "Significant control gaps exist. Recommend focused remediation period before engaging auditor.")
        } else {
            ("Not Ready", "not-ready", "Major control deficiencies present. Substantial implementation work required before audit readiness.")
        };

        let observation_period = if summary.compliance_score >= 75.0 {
            "Organization may be ready for 6-month observation period."
        } else {
            "Consider extending observation period to 12 months to demonstrate sustained control operation."
        };

        format!(
            r#"    <div class="audit-readiness">
        <h4>SOC 2 Type II Audit Readiness Assessment</h4>
        <div class="readiness-card readiness-{}">
            <div class="readiness-header">
                <strong>Readiness Level: {}</strong>
            </div>
            <p>{}</p>
        </div>
        <h5>Observation Period Recommendation</h5>
        <p>{}</p>
        <h5>Type II Audit Requirements</h5>
        <ul>
            <li><strong>Observation Period:</strong> Minimum 6 months of control operation evidence</li>
            <li><strong>Control Testing:</strong> Auditor samples and tests controls throughout period</li>
            <li><strong>Management Description:</strong> Detailed description of system and controls</li>
            <li><strong>Written Assertion:</strong> Management's assertion on control design and operation</li>
        </ul>
    </div>
"#,
            readiness.1,
            readiness.0,
            readiness.2,
            observation_period
        )
    }
}

/// SOC 2 specific recommendation structure
struct Soc2Recommendation {
    priority: &'static str,
    category: String,
    criteria: String,
    recommendation: String,
}

/// Get Trust Services Criteria categories
fn get_trust_services_criteria() -> Vec<(&'static str, &'static str, &'static str, bool)> {
    vec![
        ("CC", "Security", "Protection against unauthorized access, use, or modification", true),
        ("A", "Availability", "System availability for operation and use as committed", false),
        ("PI", "Processing Integrity", "System processing is complete, valid, accurate, and timely", false),
        ("C", "Confidentiality", "Information designated as confidential is protected", false),
        ("P", "Privacy", "Personal information is collected, used, retained, disclosed, and disposed properly", false),
    ]
}

/// Get Common Criteria (CC) series for Security
fn get_common_criteria_series() -> Vec<(&'static str, &'static str)> {
    vec![
        ("CC1", "Control Environment"),
        ("CC2", "Communication and Information"),
        ("CC3", "Risk Assessment"),
        ("CC4", "Monitoring Activities"),
        ("CC5", "Control Activities"),
        ("CC6", "Logical and Physical Access Controls"),
        ("CC7", "System Operations"),
        ("CC8", "Change Management"),
        ("CC9", "Risk Mitigation"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::types::{CategorySummary, ComplianceFramework};

    fn create_test_summary() -> FrameworkSummary {
        FrameworkSummary {
            framework: ComplianceFramework::Soc2,
            total_controls: 50,
            compliant: 35,
            non_compliant: 5,
            partially_compliant: 8,
            not_applicable: 2,
            not_assessed: 0,
            manual_overrides: 0,
            compliance_score: 82.0,
            by_category: vec![
                CategorySummary {
                    category: "CC - Security".to_string(),
                    total: 25,
                    compliant: 20,
                    non_compliant: 2,
                    percentage: 85.0,
                },
                CategorySummary {
                    category: "A - Availability".to_string(),
                    total: 9,
                    compliant: 8,
                    non_compliant: 0,
                    percentage: 90.0,
                },
                CategorySummary {
                    category: "C - Confidentiality".to_string(),
                    total: 10,
                    compliant: 6,
                    non_compliant: 2,
                    percentage: 75.0,
                },
            ],
        }
    }

    #[test]
    fn test_soc2_formatter_basics() {
        let formatter = Soc2Formatter;
        assert_eq!(formatter.framework_name(), "SOC 2 Type II");
        assert_eq!(formatter.framework_id(), "soc2");
    }

    #[test]
    fn test_generate_section() {
        let formatter = Soc2Formatter;
        let summary = create_test_summary();
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("SOC 2 Type II Compliance Assessment"));
        assert!(html.contains("Trust Services Categories"));
        assert!(html.contains("Common Criteria (Security) Status"));
        assert!(html.contains("Audit Readiness Assessment"));
    }

    #[test]
    fn test_audit_readiness_levels() {
        let formatter = Soc2Formatter;

        // High readiness
        let mut summary = create_test_summary();
        summary.compliance_score = 95.0;
        let html = formatter.generate_section(&summary, false);
        assert!(html.contains("Readiness Level: High"));

        // Moderate readiness
        summary.compliance_score = 80.0;
        let html = formatter.generate_section(&summary, false);
        assert!(html.contains("Readiness Level: Moderate"));

        // Low readiness
        summary.compliance_score = 60.0;
        let html = formatter.generate_section(&summary, false);
        assert!(html.contains("Readiness Level: Low"));
    }
}
