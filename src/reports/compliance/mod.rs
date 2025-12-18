//! Compliance Report Framework Formatters
//!
//! This module provides framework-specific formatting for compliance reports.
//! Each supported compliance framework has its own formatter that implements
//! the `FrameworkFormatter` trait for consistent report generation.
//!
//! ## Supported Frameworks
//! - PCI-DSS 4.0 - Payment Card Industry Data Security Standard
//! - NIST 800-53 Rev 5 - Security and Privacy Controls
//! - NIST CSF - Cybersecurity Framework
//! - HIPAA Security Rule - Healthcare data protection
//! - SOC 2 Type II - Trust Services Criteria
//!
//! ## Usage
//! ```rust,ignore
//! use crate::reports::compliance::{get_formatter, generate_framework_section};
//! use crate::compliance::types::ComplianceFramework;
//!
//! let formatter = get_formatter(ComplianceFramework::PciDss);
//! let section_html = formatter.generate_section(&framework_summary, true);
//! ```

#![allow(dead_code)]

pub mod common;
pub mod pci_dss;
pub mod nist;
pub mod hipaa;
pub mod soc2;

// Re-export commonly used items
pub use common::{
    get_score_class, get_score_label, html_escape,
    generate_compliance_chart, generate_category_breakdown, get_compliance_css,
    FrameworkFormatter,
};
pub use pci_dss::PciDssFormatter;
pub use nist::{Nist80053Formatter, NistCsfFormatter};
pub use hipaa::HipaaFormatter;
pub use soc2::Soc2Formatter;

use crate::compliance::types::{ComplianceFramework, FrameworkSummary};

/// Get the appropriate formatter for a compliance framework
pub fn get_formatter(framework: ComplianceFramework) -> Box<dyn FrameworkFormatter> {
    match framework {
        ComplianceFramework::PciDss4 => Box::new(PciDssFormatter),
        ComplianceFramework::Nist80053 => Box::new(Nist80053Formatter),
        ComplianceFramework::NistCsf => Box::new(NistCsfFormatter),
        ComplianceFramework::Hipaa => Box::new(HipaaFormatter),
        ComplianceFramework::Soc2 => Box::new(Soc2Formatter),
        // Default to generic formatter for other frameworks
        _ => Box::new(GenericFormatter::new(framework)),
    }
}

/// Generate a framework-specific section for a compliance report
pub fn generate_framework_section(summary: &FrameworkSummary, include_evidence: bool) -> String {
    let formatter = get_formatter(summary.framework);
    formatter.generate_section(summary, include_evidence)
}

/// Generic formatter for frameworks without specific formatters
pub struct GenericFormatter {
    framework: ComplianceFramework,
}

impl GenericFormatter {
    pub fn new(framework: ComplianceFramework) -> Self {
        Self { framework }
    }
}

impl FrameworkFormatter for GenericFormatter {
    fn framework_name(&self) -> &'static str {
        self.framework.name()
    }

    fn framework_id(&self) -> &'static str {
        self.framework.id()
    }

    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String {
        let mut html = String::new();

        // Framework header
        html.push_str(&format!(
            r#"<div class="framework-section" id="{}">
    <h3>{} Compliance Assessment</h3>
    <p class="framework-description">{}</p>
"#,
            self.framework.id(),
            self.framework.name(),
            self.framework.description()
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
            <p><strong>Findings:</strong> {}</p>
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
        let mut html = String::from("    <h4>Recommendations</h4>\n    <ul class=\"recommendations-list\">\n");

        for cat in &summary.by_category {
            if cat.non_compliant > 0 {
                let priority = if cat.percentage < 50.0 { "High" } else { "Medium" };
                html.push_str(&format!(
                    r#"        <li>
            <span class="priority-{}">[{}]</span>
            <strong>{}:</strong> Address {} non-compliant controls (current score: {:.1}%)
        </li>
"#,
                    priority.to_lowercase(),
                    priority,
                    html_escape(&cat.category),
                    cat.non_compliant,
                    cat.percentage
                ));
            }
        }

        if summary.by_category.iter().all(|c| c.non_compliant == 0) {
            html.push_str("        <li>All assessed controls are compliant or partially compliant. Continue monitoring and improvement efforts.</li>\n");
        }

        html.push_str("    </ul>\n");
        html
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::types::CategorySummary;

    fn create_test_summary(framework: ComplianceFramework) -> FrameworkSummary {
        FrameworkSummary {
            framework,
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
                    category: "Test Category".to_string(),
                    total: 10,
                    compliant: 8,
                    non_compliant: 2,
                    percentage: 80.0,
                },
            ],
        }
    }

    #[test]
    fn test_get_formatter_returns_correct_type() {
        let pci_formatter = get_formatter(ComplianceFramework::PciDss4);
        assert_eq!(pci_formatter.framework_id(), "pci_dss");

        let nist_formatter = get_formatter(ComplianceFramework::Nist80053);
        assert_eq!(nist_formatter.framework_id(), "nist_800_53");

        let hipaa_formatter = get_formatter(ComplianceFramework::Hipaa);
        assert_eq!(hipaa_formatter.framework_id(), "hipaa");

        let soc2_formatter = get_formatter(ComplianceFramework::Soc2);
        assert_eq!(soc2_formatter.framework_id(), "soc2");
    }

    #[test]
    fn test_generate_framework_section() {
        let summary = create_test_summary(ComplianceFramework::PciDss4);
        let html = generate_framework_section(&summary, true);

        assert!(html.contains("PCI-DSS"));
        assert!(html.contains("75.0%"));
    }

    #[test]
    fn test_generic_formatter() {
        let formatter = GenericFormatter::new(ComplianceFramework::CisBenchmarks);
        let summary = create_test_summary(ComplianceFramework::CisBenchmarks);
        let html = formatter.generate_section(&summary, true);

        assert!(html.contains("Compliance Assessment"));
        assert!(html.contains("75.0%"));
    }
}
