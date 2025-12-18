//! Common utilities for compliance report generation
//!
//! This module contains shared functionality used across all framework-specific
//! compliance report formatters including CSS styling, helper functions, and traits.

use crate::compliance::types::{CategorySummary, FrameworkSummary};

/// Trait for framework-specific report formatters
pub trait FrameworkFormatter {
    /// Get the framework name for display
    fn framework_name(&self) -> &'static str;

    /// Get the framework ID
    fn framework_id(&self) -> &'static str;

    /// Generate framework-specific HTML section
    fn generate_section(&self, summary: &FrameworkSummary, include_evidence: bool) -> String;

    /// Generate framework-specific recommendations
    fn generate_recommendations(&self, summary: &FrameworkSummary) -> String;
}

/// Get CSS class for compliance score
pub fn get_score_class(score: f32) -> &'static str {
    if score >= 80.0 {
        "high"
    } else if score >= 60.0 {
        "medium"
    } else {
        "low"
    }
}

/// Get human-readable label for compliance score
pub fn get_score_label(score: f32) -> &'static str {
    if score >= 80.0 {
        "Good Compliance"
    } else if score >= 60.0 {
        "Moderate Compliance"
    } else {
        "Poor Compliance"
    }
}

/// Escape HTML special characters
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Convert rating string to human-readable label
pub fn rating_to_label(rating: &str) -> &'static str {
    match rating.to_lowercase().as_str() {
        "compliant" => "Compliant",
        "non_compliant" | "noncompliant" => "Non-Compliant",
        "partial" | "partially_compliant" => "Partially Compliant",
        "not_applicable" | "notapplicable" => "Not Applicable",
        "not_assessed" | "notassessed" => "Not Assessed",
        _ => "Unknown",
    }
}

/// Generate SVG compliance chart for a framework
pub fn generate_compliance_chart(summary: &FrameworkSummary) -> String {
    let compliant = summary.compliant as f32;
    let partial = summary.partially_compliant as f32;
    let non_compliant = summary.non_compliant as f32;
    let not_applicable = summary.not_applicable as f32;
    let total = compliant + partial + non_compliant + not_applicable;

    if total == 0.0 {
        return String::from("<p class=\"no-data\">No controls assessed</p>");
    }

    // Calculate percentages
    let compliant_pct = (compliant / total) * 100.0;
    let partial_pct = (partial / total) * 100.0;
    let non_compliant_pct = (non_compliant / total) * 100.0;
    let not_applicable_pct = (not_applicable / total) * 100.0;

    // Generate stacked bar chart
    format!(
        r#"
<div class="compliance-chart">
    <div class="chart-bar">
        <div class="bar-segment compliant" style="width: {:.1}%;" title="Compliant: {:.0} ({:.1}%)"></div>
        <div class="bar-segment partial" style="width: {:.1}%;" title="Partial: {:.0} ({:.1}%)"></div>
        <div class="bar-segment non-compliant" style="width: {:.1}%;" title="Non-Compliant: {:.0} ({:.1}%)"></div>
        <div class="bar-segment not-applicable" style="width: {:.1}%;" title="N/A: {:.0} ({:.1}%)"></div>
    </div>
    <div class="chart-legend">
        <span class="legend-item"><span class="legend-color compliant"></span> Compliant ({:.0})</span>
        <span class="legend-item"><span class="legend-color partial"></span> Partial ({:.0})</span>
        <span class="legend-item"><span class="legend-color non-compliant"></span> Non-Compliant ({:.0})</span>
        <span class="legend-item"><span class="legend-color not-applicable"></span> N/A ({:.0})</span>
    </div>
</div>
"#,
        compliant_pct, compliant, compliant_pct,
        partial_pct, partial, partial_pct,
        non_compliant_pct, non_compliant, non_compliant_pct,
        not_applicable_pct, not_applicable, not_applicable_pct,
        compliant, partial, non_compliant, not_applicable
    )
}

/// Generate category breakdown HTML for a framework
pub fn generate_category_breakdown(categories: &[CategorySummary]) -> String {
    if categories.is_empty() {
        return String::from("<p class=\"no-data\">No categories available</p>");
    }

    let mut html = String::from("<div class=\"category-breakdown\">\n");

    for cat in categories {
        let score_class = get_score_class(cat.percentage);
        // Note: CategorySummary only tracks compliant and non_compliant, not partial
        let partial_count = cat.total.saturating_sub(cat.compliant + cat.non_compliant);
        html.push_str(&format!(
            r#"    <div class="category-item">
        <div class="category-header">
            <span class="category-name">{}</span>
            <span class="category-score score-{}">{:.1}%</span>
        </div>
        <div class="category-stats">
            <span class="stat compliant">{} compliant</span>
            <span class="stat partial">{} other</span>
            <span class="stat non-compliant">{} non-compliant</span>
        </div>
    </div>
"#,
            html_escape(&cat.category),
            score_class,
            cat.percentage,
            cat.compliant,
            partial_count,
            cat.non_compliant
        ));
    }

    html.push_str("</div>\n");
    html
}

/// Get the complete CSS stylesheet for compliance reports
pub fn get_compliance_css() -> &'static str {
    r#"
/* Reset and base */
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    color: #1a1a2e;
    background: #fff;
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Cover page */
.cover-page {
    min-height: 90vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    page-break-after: always;
    border-bottom: 2px solid #e2e8f0;
    margin-bottom: 40px;
    padding-bottom: 40px;
}
.classification {
    background: #ef4444;
    color: white;
    padding: 8px 24px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 30px;
    border-radius: 4px;
}
.shield-icon {
    color: #3b82f6;
    margin-bottom: 20px;
}
.report-title {
    font-size: 2.5rem;
    color: #1e3a5f;
    margin-bottom: 10px;
}
.subtitle {
    font-size: 1.2rem;
    color: #64748b;
    margin-bottom: 40px;
}
.cover-meta {
    margin-bottom: 40px;
}
.cover-meta p {
    margin: 8px 0;
    color: #475569;
}
.cover-summary {
    display: flex;
    gap: 50px;
}
.summary-stat {
    text-align: center;
}
.stat-value {
    display: block;
    font-size: 3rem;
    font-weight: bold;
    color: #1e3a5f;
}
.stat-label {
    color: #64748b;
    text-transform: uppercase;
    font-size: 0.85rem;
    letter-spacing: 1px;
}
.summary-stat.score-high .stat-value { color: #22c55e; }
.summary-stat.score-medium .stat-value { color: #eab308; }
.summary-stat.score-low .stat-value { color: #ef4444; }

/* Sections */
.section {
    margin-bottom: 40px;
    page-break-inside: avoid;
}
.section h2 {
    font-size: 1.75rem;
    color: #1e3a5f;
    border-bottom: 3px solid #3b82f6;
    padding-bottom: 10px;
    margin-bottom: 20px;
}
.section h3 {
    font-size: 1.25rem;
    color: #334155;
    margin: 25px 0 15px;
}
.section h4 {
    font-size: 1.1rem;
    color: #475569;
    margin: 20px 0 10px;
}

/* Score summary */
.score-summary {
    display: flex;
    align-items: center;
    gap: 40px;
    background: #f8fafc;
    padding: 30px;
    border-radius: 8px;
    margin: 20px 0;
}
.score-badge {
    text-align: center;
    padding: 30px;
    border-radius: 12px;
    min-width: 150px;
    border: 3px solid;
}
.score-badge.score-high {
    background: #f0fdf4;
    border-color: #22c55e;
    color: #166534;
}
.score-badge.score-medium {
    background: #fefce8;
    border-color: #eab308;
    color: #854d0e;
}
.score-badge.score-low {
    background: #fef2f2;
    border-color: #ef4444;
    color: #991b1b;
}
.score-value {
    display: block;
    font-size: 3rem;
    font-weight: bold;
}
.score-label {
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.score-details p {
    margin: 8px 0;
    color: #475569;
}
.score-details strong {
    color: #1e3a5f;
}

/* Framework cards */
.framework-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
    gap: 20px;
    margin: 20px 0;
}
.framework-card {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}
.framework-card h4 {
    margin: 0 0 15px;
    color: #1e3a5f;
}
.framework-card .score {
    font-size: 2rem;
    font-weight: bold;
    margin-bottom: 10px;
}
.framework-card .score.score-high { color: #22c55e; }
.framework-card .score.score-medium { color: #eab308; }
.framework-card .score.score-low { color: #ef4444; }
.framework-stats {
    display: flex;
    gap: 15px;
    flex-wrap: wrap;
    margin-top: 15px;
}
.framework-stats .stat {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 0.9rem;
}
.framework-stats .stat::before {
    content: '';
    width: 10px;
    height: 10px;
    border-radius: 50%;
}
.stat.compliant::before { background: #22c55e; }
.stat.partial::before { background: #eab308; }
.stat.non-compliant::before { background: #ef4444; }
.stat.not-applicable::before { background: #94a3b8; }

/* Tables */
.info-table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}
.info-table th,
.info-table td {
    padding: 12px 15px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
}
.info-table th {
    background: #f8fafc;
    font-weight: 600;
    color: #334155;
    width: 200px;
}
.info-table tr:hover {
    background: #f8fafc;
}

/* Control tables */
.control-table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    font-size: 0.9rem;
}
.control-table th {
    background: #1e3a5f;
    color: white;
    padding: 12px 15px;
    text-align: left;
    font-weight: 600;
}
.control-table td {
    padding: 12px 15px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
}
.control-table tr:nth-child(even) {
    background: #f8fafc;
}
.control-table tr:hover {
    background: #f1f5f9;
}

/* Status badges */
.status-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
    text-transform: uppercase;
}
.status-compliant {
    background: #dcfce7;
    color: #166534;
}
.status-partial {
    background: #fef9c3;
    color: #854d0e;
}
.status-non-compliant {
    background: #fee2e2;
    color: #991b1b;
}
.status-not-applicable {
    background: #f1f5f9;
    color: #64748b;
}
.status-not-assessed {
    background: #e2e8f0;
    color: #475569;
}

/* Severity badges */
.severity-critical {
    background: #7f1d1d;
    color: white;
}
.severity-high {
    background: #dc2626;
    color: white;
}
.severity-medium {
    background: #f59e0b;
    color: white;
}
.severity-low {
    background: #3b82f6;
    color: white;
}
.severity-info {
    background: #6b7280;
    color: white;
}

/* Evidence section */
.evidence-section {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    margin: 15px 0;
}
.evidence-section h5 {
    color: #334155;
    margin-bottom: 15px;
}
.evidence-item {
    padding: 10px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    margin: 10px 0;
}
.evidence-item .type {
    font-weight: 600;
    color: #3b82f6;
    margin-bottom: 5px;
}
.evidence-item .content {
    color: #475569;
    font-size: 0.9rem;
}

/* Findings list */
.finding-item {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-left: 4px solid;
    border-radius: 4px;
    padding: 15px;
    margin: 15px 0;
}
.finding-item.severity-critical { border-left-color: #7f1d1d; }
.finding-item.severity-high { border-left-color: #dc2626; }
.finding-item.severity-medium { border-left-color: #f59e0b; }
.finding-item.severity-low { border-left-color: #3b82f6; }
.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.finding-title {
    font-weight: 600;
    color: #1e3a5f;
}
.finding-description {
    color: #475569;
    margin: 10px 0;
}
.finding-meta {
    font-size: 0.85rem;
    color: #64748b;
}

/* Recommendations */
.recommendations-list {
    list-style: none;
}
.recommendations-list li {
    padding: 15px;
    margin: 10px 0;
    background: #f0f9ff;
    border-left: 4px solid #3b82f6;
    border-radius: 4px;
}
.recommendations-list li strong {
    color: #1e3a5f;
}

/* Charts */
.compliance-chart {
    margin: 20px 0;
}
.chart-bar {
    display: flex;
    height: 30px;
    border-radius: 15px;
    overflow: hidden;
    background: #e2e8f0;
}
.bar-segment {
    height: 100%;
    transition: width 0.3s;
}
.bar-segment.compliant { background: #22c55e; }
.bar-segment.partial { background: #eab308; }
.bar-segment.non-compliant { background: #ef4444; }
.bar-segment.not-applicable { background: #94a3b8; }
.chart-legend {
    display: flex;
    gap: 20px;
    margin-top: 10px;
    font-size: 0.85rem;
}
.legend-item {
    display: flex;
    align-items: center;
    gap: 5px;
}
.legend-color {
    width: 12px;
    height: 12px;
    border-radius: 3px;
}
.legend-color.compliant { background: #22c55e; }
.legend-color.partial { background: #eab308; }
.legend-color.non-compliant { background: #ef4444; }
.legend-color.not-applicable { background: #94a3b8; }

/* Category breakdown */
.category-breakdown {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 15px;
    margin: 20px 0;
}
.category-item {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 15px;
}
.category-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}
.category-name {
    font-weight: 600;
    color: #1e3a5f;
}
.category-score {
    font-weight: bold;
    padding: 4px 10px;
    border-radius: 4px;
}
.category-score.score-high { background: #dcfce7; color: #166534; }
.category-score.score-medium { background: #fef9c3; color: #854d0e; }
.category-score.score-low { background: #fee2e2; color: #991b1b; }
.category-stats {
    display: flex;
    gap: 10px;
    font-size: 0.85rem;
    color: #64748b;
}

/* Footer */
.report-footer {
    margin-top: 60px;
    padding-top: 20px;
    border-top: 2px solid #e2e8f0;
    text-align: center;
    color: #64748b;
    font-size: 0.9rem;
}
.report-footer p {
    margin: 5px 0;
}
.disclaimer {
    font-style: italic;
    color: #94a3b8;
    margin-top: 10px;
}

/* Print styles */
@media print {
    body {
        max-width: 100%;
        padding: 0;
    }
    .section {
        page-break-inside: avoid;
    }
    .cover-page {
        min-height: 100vh;
    }
    .framework-card,
    .finding-item,
    .category-item {
        break-inside: avoid;
    }
}

/* Combined report styles */
.assessment-method {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
}
.method-automated {
    background: #dbeafe;
    color: #1d4ed8;
}
.method-manual {
    background: #f3e8ff;
    color: #7c3aed;
}
.method-both {
    background: #d1fae5;
    color: #047857;
}

.manual-details {
    background: #faf5ff;
    border: 1px solid #e9d5ff;
    border-radius: 6px;
    padding: 12px;
    margin-top: 10px;
    font-size: 0.9rem;
}
.manual-details .assessor {
    color: #7c3aed;
    font-weight: 600;
}
.manual-details .date {
    color: #64748b;
}
.manual-details .notes {
    margin-top: 8px;
    color: #475569;
    font-style: italic;
}

.criteria-ratings {
    margin-top: 10px;
}
.criterion-item {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid #e2e8f0;
}
.criterion-item:last-child {
    border-bottom: none;
}
.criterion-name {
    color: #334155;
}
.criterion-rating {
    font-weight: 600;
}
.criterion-rating.rating-meets { color: #22c55e; }
.criterion-rating.rating-partially { color: #eab308; }
.criterion-rating.rating-does-not { color: #ef4444; }
.criterion-rating.rating-na { color: #64748b; }

.evidence-attachments {
    margin-top: 10px;
}
.evidence-attachments h6 {
    color: #475569;
    margin-bottom: 8px;
}
.attachment-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    margin: 4px 0;
}
.attachment-type {
    font-size: 0.75rem;
    padding: 2px 6px;
    border-radius: 3px;
    background: #f1f5f9;
    color: #475569;
}
.attachment-title {
    color: #334155;
}

/* Statistics summary */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin: 20px 0;
}
.stat-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
}
.stat-card .value {
    font-size: 2rem;
    font-weight: bold;
    color: #1e3a5f;
}
.stat-card .label {
    color: #64748b;
    font-size: 0.9rem;
    margin-top: 5px;
}

/* Code blocks for evidence */
.code-block {
    background: #f8fafc;
    padding: 10px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.85rem;
}
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_score_class() {
        assert_eq!(get_score_class(100.0), "high");
        assert_eq!(get_score_class(80.0), "high");
        assert_eq!(get_score_class(79.9), "medium");
        assert_eq!(get_score_class(60.0), "medium");
        assert_eq!(get_score_class(59.9), "low");
        assert_eq!(get_score_class(0.0), "low");
    }

    #[test]
    fn test_get_score_label() {
        assert_eq!(get_score_label(85.0), "Good Compliance");
        assert_eq!(get_score_label(70.0), "Moderate Compliance");
        assert_eq!(get_score_label(40.0), "Poor Compliance");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_rating_to_label() {
        assert_eq!(rating_to_label("compliant"), "Compliant");
        assert_eq!(rating_to_label("non_compliant"), "Non-Compliant");
        assert_eq!(rating_to_label("partial"), "Partially Compliant");
        assert_eq!(rating_to_label("not_applicable"), "Not Applicable");
        assert_eq!(rating_to_label("unknown_value"), "Unknown");
    }
}
