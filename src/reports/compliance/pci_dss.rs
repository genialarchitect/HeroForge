//! PCI-DSS Compliance Report Formatter
//!
//! This module provides PCI-DSS specific formatting for compliance reports,
//! including requirement breakdowns, SAQ guidance, and PCI-specific recommendations.

use crate::compliance::types::{ControlStatus, FrameworkSummary};
use super::common::{get_score_class, html_escape, generate_compliance_chart, generate_category_breakdown, FrameworkFormatter};

/// PCI-DSS 4.0 compliance report formatter
pub struct PciDssFormatter;

impl FrameworkFormatter for PciDssFormatter {
    fn framework_name(&self) -> &'static str {
        "PCI-DSS 4.0"
    }

    fn framework_id(&self) -> &'static str {
        "pci_dss"
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="pci-dss">
    <h3>PCI-DSS 4.0 Compliance Assessment</h3>
    <p class="framework-description">Payment Card Industry Data Security Standard version 4.0
    provides a baseline of technical and operational requirements designed to protect payment account data.</p>
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
            <p><strong>Total Controls:</strong> {}</p>
            <p><strong>Compliant:</strong> {} | <strong>Partial:</strong> {} | <strong>Non-Compliant:</strong> {}</p>
            <p><strong>Total Findings:</strong> {}</p>
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
        html.push_str("    <h4>Compliance Distribution</h4>\n");
        html.push_str(&generate_compliance_chart(summary));

        // Requirements breakdown
        html.push_str(&self.generate_requirements_breakdown(summary));

        // Category breakdown
        html.push_str("    <h4>Category Analysis</h4>\n");
        html.push_str(&generate_category_breakdown(&summary.by_category));

        // SAQ Guidance
        html.push_str(&self.generate_saq_guidance(summary));

        // Recommendations
        if include_evidence {
            html.push_str(&self.generate_recommendations(summary));
        }

        html.push_str("</div>\n");
        html
    }

    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String {
        let mut recommendations = Vec::new();

        // Analyze non-compliant areas
        for cat in &summary.by_category {
            if cat.non_compliant > 0 {
                recommendations.push(PciDssRecommendation {
                    priority: if cat.percentage < 50.0 { "High" } else { "Medium" },
                    requirement: cat.category.clone(),
                    recommendation: format!(
                        "Address {} non-compliant controls in {} to improve compliance score from {:.1}%",
                        cat.non_compliant, cat.category, cat.percentage
                    ),
                });
            }
        }

        // Generate HTML
        let mut html = String::from("    <h4>Remediation Recommendations</h4>\n    <ul class=\"recommendations-list\">\n");

        for rec in &recommendations {
            html.push_str(&format!(
                r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{}:</strong> {}
        </li>
"#,
                rec.priority.to_lowercase(),
                rec.priority,
                html_escape(&rec.requirement),
                html_escape(&rec.recommendation)
            ));
        }

        if recommendations.is_empty() {
            html.push_str("        <li>No critical remediation items identified. Continue maintaining current controls.</li>\n");
        }

        html.push_str("    </ul>\n");
        html
    }
}

impl PciDssFormatter {
    /// Generate PCI-DSS requirements breakdown
    fn generate_requirements_breakdown(&self, summary: &FrameworkSummary) -> String {
        let requirements = get_principal_requirements();

        let mut html = String::from("    <h4>Principal Requirements Status</h4>\n    <table class=\"control-table\">\n");
        html.push_str("        <tr><th>Requirement</th><th>Description</th><th>Status</th></tr>\n");

        for (req_num, req_name) in requirements {
            // Find matching category
            let status = summary.by_category.iter()
                .find(|c| c.category.starts_with(&format!("Req {}", req_num)))
                .map(|c| {
                    if c.percentage >= 100.0 { ControlStatus::Compliant }
                    else if c.percentage >= 50.0 { ControlStatus::PartiallyCompliant }
                    else { ControlStatus::NonCompliant }
                })
                .unwrap_or(ControlStatus::NotAssessed);

            let status_class = match status {
                ControlStatus::Compliant => "status-compliant",
                ControlStatus::PartiallyCompliant => "status-partial",
                ControlStatus::NonCompliant => "status-non-compliant",
                _ => "status-not-assessed",
            };

            let status_text = match status {
                ControlStatus::Compliant => "Compliant",
                ControlStatus::PartiallyCompliant => "Partial",
                ControlStatus::NonCompliant => "Non-Compliant",
                _ => "Not Assessed",
            };

            html.push_str(&format!(
                "        <tr><td>Requirement {}</td><td>{}</td><td><span class=\"status-badge {}\">{}</span></td></tr>\n",
                req_num, html_escape(req_name), status_class, status_text
            ));
        }

        html.push_str("    </table>\n");
        html
    }

    /// Generate SAQ (Self-Assessment Questionnaire) guidance
    fn generate_saq_guidance(&self, summary: &FrameworkSummary) -> String {
        let mut html = String::from(r#"    <div class="saq-guidance">
        <h4>Self-Assessment Questionnaire (SAQ) Guidance</h4>
        <p>Based on your compliance profile, consider the following SAQ types:</p>
        <ul>
"#);

        if summary.compliance_score >= 90.0 {
            html.push_str(r#"            <li><strong>SAQ A:</strong> Card-not-present merchants (ecommerce/MOTO) that outsource all cardholder data functions</li>
            <li><strong>SAQ A-EP:</strong> E-commerce merchants with websites that do not receive cardholder data but affect payment security</li>
"#);
        } else if summary.compliance_score >= 70.0 {
            html.push_str(r#"            <li><strong>SAQ B:</strong> Merchants using imprint machines or standalone dial-out terminals</li>
            <li><strong>SAQ B-IP:</strong> Merchants using standalone PTS-approved payment terminals with IP connection</li>
            <li><strong>SAQ C:</strong> Merchants with payment application systems connected to the Internet</li>
"#);
        } else {
            html.push_str(r#"            <li><strong>SAQ C-VT:</strong> Merchants using web-based virtual terminals</li>
            <li><strong>SAQ P2PE:</strong> Merchants using validated PCI-listed P2PE solutions</li>
            <li><strong>SAQ D:</strong> Full self-assessment for merchants not fitting other SAQ criteria</li>
"#);
        }

        html.push_str("        </ul>\n    </div>\n");
        html
    }
}

/// PCI-DSS specific recommendation
struct PciDssRecommendation {
    priority: &'static str,
    requirement: String,
    recommendation: String,
}

/// Get the 12 principal PCI-DSS 4.0 requirements
fn get_principal_requirements() -> Vec<(&'static str, &'static str)> {
    vec![
        ("1", "Install and Maintain Network Security Controls"),
        ("2", "Apply Secure Configurations to All System Components"),
        ("3", "Protect Stored Account Data"),
        ("4", "Protect Cardholder Data with Strong Cryptography During Transmission"),
        ("5", "Protect All Systems and Networks from Malicious Software"),
        ("6", "Develop and Maintain Secure Systems and Software"),
        ("7", "Restrict Access to System Components and Cardholder Data"),
        ("8", "Identify Users and Authenticate Access"),
        ("9", "Restrict Physical Access to Cardholder Data"),
        ("10", "Log and Monitor All Access to System Components and Cardholder Data"),
        ("11", "Test Security of Systems and Networks Regularly"),
        ("12", "Support Information Security with Organizational Policies and Programs"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::types::{CategorySummary, ComplianceFramework};

    fn create_test_summary() -> FrameworkSummary {
        FrameworkSummary {
            framework: ComplianceFramework::PciDss4,
            total_controls: 50,
            compliant: 30,
            non_compliant: 5,
            partially_compliant: 10,
            not_applicable: 5,
            not_assessed: 0,
            manual_overrides: 0,
            compliance_score: 75.0,
            by_category: vec![
                CategorySummary {
                    category: "Req 1 - Network Security".to_string(),
                    total: 10,
                    compliant: 8,
                    non_compliant: 2,
                    percentage: 80.0,
                },
            ],
        }
    }

    #[test]
    fn test_pci_dss_formatter_name() {
        let formatter = PciDssFormatter;
        assert_eq!(formatter.framework_name(), "PCI-DSS 4.0");
        assert_eq!(formatter.framework_id(), "pci_dss");
    }

    #[test]
    fn test_generate_section() {
        let formatter = PciDssFormatter;
        let summary = create_test_summary();
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("PCI-DSS 4.0 Compliance Assessment"));
        assert!(html.contains("75.0%"));
        assert!(html.contains("Principal Requirements Status"));
    }
}
