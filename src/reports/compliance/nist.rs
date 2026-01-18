//! NIST Compliance Report Formatters
//!
//! This module provides formatters for both NIST 800-53 and NIST Cybersecurity Framework (CSF)
//! compliance reports, including control family breakdowns, impact levels, and tier assessments.

use crate::compliance::types::{ControlStatus, FrameworkSummary};
use super::common::{get_score_class, html_escape, generate_compliance_chart, generate_category_breakdown, FrameworkFormatter};

/// NIST 800-53 Rev 5 compliance report formatter
pub struct Nist80053Formatter;

impl FrameworkFormatter for Nist80053Formatter {
    fn framework_name(&self) -> &'static str {
        "NIST 800-53 Rev 5"
    }

    fn framework_id(&self) -> &'static str {
        "nist_800_53"
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="nist-800-53">
    <h3>NIST 800-53 Rev 5 Compliance Assessment</h3>
    <p class="framework-description">NIST Special Publication 800-53 provides a catalog of security and privacy controls
    for federal information systems and organizations to protect organizational operations, assets, individuals,
    other organizations, and the Nation from various threats.</p>
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
        html.push_str("    <h4>Control Implementation Status</h4>\n");
        html.push_str(&generate_compliance_chart(summary));

        // Control families breakdown
        html.push_str(&self.generate_control_families_breakdown(summary));

        // Category breakdown
        html.push_str("    <h4>Control Family Analysis</h4>\n");
        html.push_str(&generate_category_breakdown(&summary.by_category));

        // Impact level guidance
        html.push_str(&self.generate_impact_level_guidance(summary));

        // Recommendations
        if include_evidence {
            html.push_str(&self.generate_recommendations(summary));
        }

        html.push_str("</div>\n");
        html
    }

    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String {
        let mut html = String::from("    <h4>Control Implementation Recommendations</h4>\n    <ul class=\"recommendations-list\">\n");

        // Analyze non-compliant areas by control family
        let families = get_control_families();
        for (family_id, family_name) in &families {
            let matching_cat = summary.by_category.iter()
                .find(|c| c.category.starts_with(family_id));

            if let Some(cat) = matching_cat {
                if cat.non_compliant > 0 {
                    let priority = if cat.percentage < 50.0 { "High" } else if cat.percentage < 75.0 { "Medium" } else { "Low" };
                    html.push_str(&format!(
                        r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{} ({}):</strong> {} controls require attention. Current score: {:.1}%
        </li>
"#,
                        priority.to_lowercase(),
                        priority,
                        html_escape(family_name),
                        family_id,
                        cat.non_compliant,
                        cat.percentage
                    ));
                }
            }
        }

        html.push_str("    </ul>\n");
        html
    }
}

impl Nist80053Formatter {
    /// Generate NIST 800-53 control families breakdown
    fn generate_control_families_breakdown(&self, summary: &FrameworkSummary) -> String {
        let families = get_control_families();

        let mut html = String::from("    <h4>Control Families Status</h4>\n    <table class=\"control-table\">\n");
        html.push_str("        <tr><th>Family</th><th>Description</th><th>Status</th><th>Score</th></tr>\n");

        for (family_id, family_name) in &families {
            let cat_info = summary.by_category.iter()
                .find(|c| c.category.starts_with(family_id));

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
                ControlStatus::Compliant => "Compliant",
                ControlStatus::PartiallyCompliant => "Partial",
                ControlStatus::NonCompliant => "Non-Compliant",
                _ => "Not Assessed",
            };

            html.push_str(&format!(
                "        <tr><td>{}</td><td>{}</td><td><span class=\"status-badge {}\">{}</span></td><td>{:.1}%</td></tr>\n",
                family_id, html_escape(family_name), status_class, status_text, score
            ));
        }

        html.push_str("    </table>\n");
        html
    }

    /// Generate FIPS 199 impact level guidance
    fn generate_impact_level_guidance(&self, summary: &FrameworkSummary) -> String {
        let impact_level = if summary.compliance_score >= 90.0 {
            ("High", "Your organization demonstrates robust control implementation suitable for high-impact systems.")
        } else if summary.compliance_score >= 70.0 {
            ("Moderate", "Control implementation is adequate for moderate-impact systems. Consider enhancing controls for high-impact requirements.")
        } else {
            ("Low", "Current controls may only be suitable for low-impact systems. Significant improvements needed for moderate/high-impact requirements.")
        };

        format!(
            r#"    <div class="impact-guidance">
        <h4>FIPS 199 Impact Level Assessment</h4>
        <div class="impact-card impact-{}">
            <strong>Suggested Impact Level: {}</strong>
            <p>{}</p>
        </div>
        <p class="note">Note: Actual impact categorization should be determined through formal system categorization process per FIPS 199.</p>
    </div>
"#,
            impact_level.0.to_lowercase(),
            impact_level.0,
            impact_level.1
        )
    }
}

/// NIST Cybersecurity Framework (CSF) compliance report formatter
pub struct NistCsfFormatter;

impl FrameworkFormatter for NistCsfFormatter {
    fn framework_name(&self) -> &'static str {
        "NIST CSF"
    }

    fn framework_id(&self) -> &'static str {
        "nist_csf"
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="nist-csf">
    <h3>NIST Cybersecurity Framework Assessment</h3>
    <p class="framework-description">The NIST Cybersecurity Framework provides a policy framework of computer security
    guidance for how organizations can assess and improve their ability to prevent, detect, and respond to cyber attacks.</p>
"#
        ));

        // Score summary
        let score_class = get_score_class(summary.compliance_score);
        html.push_str(&format!(
            r#"    <div class="score-summary">
        <div class="score-badge score-{}">
            <span class="score-value">{:.1}%</span>
            <span class="score-label">Maturity Score</span>
        </div>
        <div class="score-details">
            <p><strong>Total Outcomes:</strong> {}</p>
            <p><strong>Achieved:</strong> {} | <strong>Partial:</strong> {} | <strong>Not Achieved:</strong> {}</p>
            <p><strong>Gaps Identified:</strong> {}</p>
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
        html.push_str("    <h4>Framework Function Coverage</h4>\n");
        html.push_str(&generate_compliance_chart(summary));

        // Core functions breakdown
        html.push_str(&self.generate_core_functions_breakdown(summary));

        // Tier assessment
        html.push_str(&self.generate_tier_assessment(summary));

        // Category breakdown
        html.push_str("    <h4>Category Analysis</h4>\n");
        html.push_str(&generate_category_breakdown(&summary.by_category));

        // Recommendations
        if include_evidence {
            html.push_str(&self.generate_recommendations(summary));
        }

        html.push_str("</div>\n");
        html
    }

    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String {
        let mut html = String::from("    <h4>Framework Implementation Recommendations</h4>\n    <ul class=\"recommendations-list\">\n");

        let functions = get_csf_functions();
        for (func_id, func_name, _desc) in &functions {
            let matching_cat = summary.by_category.iter()
                .find(|c| c.category.starts_with(func_id) || c.category.contains(func_name));

            if let Some(cat) = matching_cat {
                if cat.non_compliant > 0 {
                    let priority = if cat.percentage < 50.0 { "High" } else if cat.percentage < 75.0 { "Medium" } else { "Low" };
                    html.push_str(&format!(
                        r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{} ({}):</strong> Improve {} outcomes to strengthen this function. Current maturity: {:.1}%
        </li>
"#,
                        priority.to_lowercase(),
                        priority,
                        html_escape(func_name),
                        func_id,
                        cat.non_compliant,
                        cat.percentage
                    ));
                }
            }
        }

        html.push_str("    </ul>\n");
        html
    }
}

impl NistCsfFormatter {
    /// Generate CSF core functions breakdown
    fn generate_core_functions_breakdown(&self, summary: &FrameworkSummary) -> String {
        let functions = get_csf_functions();

        let mut html = String::from("    <h4>Core Functions Status</h4>\n    <div class=\"framework-grid\">\n");

        for (func_id, func_name, func_desc) in &functions {
            let cat_info = summary.by_category.iter()
                .find(|c| c.category.starts_with(func_id) || c.category.contains(func_name));

            let score = cat_info.map(|c| c.percentage).unwrap_or(0.0);
            let score_class = get_score_class(score);

            html.push_str(&format!(
                r#"        <div class="framework-card">
            <h4>{} ({})</h4>
            <div class="score score-{}">{:.1}%</div>
            <p>{}</p>
        </div>
"#,
                html_escape(func_name),
                func_id,
                score_class,
                score,
                html_escape(func_desc)
            ));
        }

        html.push_str("    </div>\n");
        html
    }

    /// Generate implementation tier assessment
    fn generate_tier_assessment(&self, summary: &FrameworkSummary) -> String {
        let tier = if summary.compliance_score >= 90.0 {
            ("Tier 4", "Adaptive", "Risk management practices are based on lessons learned and predictive indicators derived from previous and current cybersecurity activities.")
        } else if summary.compliance_score >= 75.0 {
            ("Tier 3", "Repeatable", "Risk management practices are formally approved and expressed as policy. Organizational cybersecurity practices are regularly updated based on business requirements and changing threat landscape.")
        } else if summary.compliance_score >= 50.0 {
            ("Tier 2", "Risk Informed", "Risk management practices are approved by management but may not be established as organizational-wide policy. There is awareness of cybersecurity risk at the organizational level.")
        } else {
            ("Tier 1", "Partial", "Risk management is ad hoc and often reactive. Cybersecurity activities are typically performed irregularly, on a case-by-case basis.")
        };

        format!(
            r#"    <div class="tier-assessment">
        <h4>Implementation Tier Assessment</h4>
        <div class="tier-card tier-{}">
            <div class="tier-header">
                <strong>{}: {}</strong>
            </div>
            <p>{}</p>
        </div>
        <p class="note">Based on current compliance score of {:.1}%. Formal tier determination requires comprehensive organizational assessment.</p>
    </div>
"#,
            tier.0.to_lowercase().replace(" ", "-"),
            tier.0,
            tier.1,
            tier.2,
            summary.compliance_score
        )
    }
}

/// Get NIST 800-53 control families
fn get_control_families() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AC", "Access Control"),
        ("AT", "Awareness and Training"),
        ("AU", "Audit and Accountability"),
        ("CA", "Assessment, Authorization, and Monitoring"),
        ("CM", "Configuration Management"),
        ("CP", "Contingency Planning"),
        ("IA", "Identification and Authentication"),
        ("IR", "Incident Response"),
        ("MA", "Maintenance"),
        ("MP", "Media Protection"),
        ("PE", "Physical and Environmental Protection"),
        ("PL", "Planning"),
        ("PM", "Program Management"),
        ("PS", "Personnel Security"),
        ("PT", "PII Processing and Transparency"),
        ("RA", "Risk Assessment"),
        ("SA", "System and Services Acquisition"),
        ("SC", "System and Communications Protection"),
        ("SI", "System and Information Integrity"),
        ("SR", "Supply Chain Risk Management"),
    ]
}

/// Get NIST CSF core functions
fn get_csf_functions() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("ID", "Identify", "Develop organizational understanding to manage cybersecurity risk"),
        ("PR", "Protect", "Implement safeguards to ensure delivery of critical services"),
        ("DE", "Detect", "Implement activities to identify cybersecurity events"),
        ("RS", "Respond", "Take action regarding detected cybersecurity events"),
        ("RC", "Recover", "Maintain plans for resilience and restore capabilities impaired by cybersecurity events"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::types::{CategorySummary, ComplianceFramework};

    fn create_test_summary(framework: ComplianceFramework) -> FrameworkSummary {
        FrameworkSummary {
            framework,
            total_controls: 50,
            compliant: 25,
            non_compliant: 7,
            partially_compliant: 8,
            not_applicable: 10,
            not_assessed: 0,
            manual_overrides: 0,
            compliance_score: 72.5,
            by_category: vec![
                CategorySummary {
                    category: "AC - Access Control".to_string(),
                    total: 10,
                    compliant: 6,
                    non_compliant: 4,
                    percentage: 75.0,
                },
                CategorySummary {
                    category: "ID - Identify".to_string(),
                    total: 10,
                    compliant: 8,
                    non_compliant: 2,
                    percentage: 80.0,
                },
            ],
        }
    }

    #[test]
    fn test_nist_800_53_formatter() {
        let formatter = Nist80053Formatter;
        assert_eq!(formatter.framework_name(), "NIST 800-53 Rev 5");
        assert_eq!(formatter.framework_id(), "nist_800_53");

        let summary = create_test_summary(ComplianceFramework::Nist80053);
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("NIST 800-53 Rev 5 Compliance Assessment"));
        assert!(html.contains("Control Families Status"));
        assert!(html.contains("FIPS 199 Impact Level Assessment"));
    }

    #[test]
    fn test_nist_csf_formatter() {
        let formatter = NistCsfFormatter;
        assert_eq!(formatter.framework_name(), "NIST CSF");
        assert_eq!(formatter.framework_id(), "nist_csf");

        let summary = create_test_summary(ComplianceFramework::NistCsf);
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("NIST Cybersecurity Framework Assessment"));
        assert!(html.contains("Core Functions Status"));
        assert!(html.contains("Implementation Tier Assessment"));
    }
}
