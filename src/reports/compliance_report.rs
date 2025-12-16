//! Compliance Report Generation
//!
//! This module generates PDF and HTML compliance reports from compliance analysis results.
//! Reports include executive summaries, framework-by-framework breakdowns, control status details,
//! evidence, remediation recommendations, and category-level charts.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

use crate::compliance::types::{
    ComplianceSummary, FrameworkSummary, CategorySummary,
};
use crate::reports::types::ReportFormat;

/// Request body for generating compliance reports
#[derive(Debug, Clone, Deserialize)]
pub struct ComplianceReportRequest {
    /// Frameworks to include in the report (empty = all from summary)
    pub frameworks: Vec<String>,
    /// Report format (pdf or html)
    pub format: ReportFormat,
    /// Whether to include evidence details
    #[serde(default = "default_include_evidence")]
    pub include_evidence: bool,
}

fn default_include_evidence() -> bool {
    true
}

/// Complete data structure for compliance report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportData {
    /// Report ID
    pub id: String,
    /// Report name/title
    pub name: String,
    /// Scan ID
    pub scan_id: String,
    /// Scan name
    pub scan_name: String,
    /// Report generation timestamp
    pub created_at: DateTime<Utc>,
    /// Scan completion timestamp
    pub scan_date: DateTime<Utc>,
    /// Compliance summary with all framework results
    pub summary: ComplianceSummary,
    /// Company name (optional)
    pub company_name: Option<String>,
    /// Assessor name (optional)
    pub assessor_name: Option<String>,
    /// Report classification (e.g., "CONFIDENTIAL")
    pub classification: Option<String>,
    /// Whether to include evidence
    pub include_evidence: bool,
}

/// Generate a compliance report
pub async fn generate(
    data: &ComplianceReportData,
    format: ReportFormat,
    reports_dir: &str,
) -> Result<(String, i64)> {
    match format {
        ReportFormat::Html => generate_html(data, reports_dir).await,
        ReportFormat::Pdf => generate_pdf(data, reports_dir).await,
        ReportFormat::Json => generate_json(data, reports_dir).await,
    }
}

/// Generate HTML compliance report
async fn generate_html(data: &ComplianceReportData, reports_dir: &str) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    let filename = format!("{}.html", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    let html_content = build_html_report(data);

    fs::write(&file_path, &html_content).await?;

    let file_size = html_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Generate PDF compliance report
async fn generate_pdf(data: &ComplianceReportData, reports_dir: &str) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    // Generate HTML first
    let html_content = build_html_report(data);

    // Write temporary HTML file
    let temp_html_path = Path::new(reports_dir).join(format!("{}_temp.html", data.id));
    fs::write(&temp_html_path, &html_content).await?;

    // Output PDF path
    let pdf_filename = format!("{}.pdf", data.id);
    let pdf_path = Path::new(reports_dir).join(&pdf_filename);

    // Use existing PDF generation logic
    let result = super::formats::pdf::try_wkhtmltopdf(&temp_html_path, &pdf_path).await;

    if result.is_err() {
        log::warn!("wkhtmltopdf failed, trying chromium...");
        super::formats::pdf::try_chromium(&temp_html_path, &pdf_path).await?;
    }

    // Clean up temp HTML
    let _ = fs::remove_file(&temp_html_path).await;

    // Get file size
    let metadata = fs::metadata(&pdf_path).await?;
    let file_size = metadata.len() as i64;

    let path_str = pdf_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Generate JSON compliance report
async fn generate_json(data: &ComplianceReportData, reports_dir: &str) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    let filename = format!("{}.json", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    let json_content = serde_json::to_string_pretty(data)?;

    fs::write(&file_path, &json_content).await?;

    let file_size = json_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Build HTML content for compliance report
fn build_html_report(data: &ComplianceReportData) -> String {
    let mut html = String::new();

    // Document head
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Compliance Report</title>
    <style>{}</style>
</head>
<body>
"#,
        html_escape(&data.name),
        get_compliance_css()
    ));

    // Cover page
    html.push_str(&generate_cover_page(data));

    // Executive summary
    html.push_str(&generate_executive_summary(data));

    // Framework-by-framework breakdown
    html.push_str(&generate_framework_breakdown(data));

    // Remediation recommendations
    html.push_str(&generate_remediation_section(data));

    // Appendix
    html.push_str(&generate_appendix(data));

    // Footer
    html.push_str(&generate_footer(data));

    html.push_str("</body>\n</html>");

    html
}

fn generate_cover_page(data: &ComplianceReportData) -> String {
    let classification = data.classification.as_deref().unwrap_or("CONFIDENTIAL");
    let company = data.company_name.as_deref().unwrap_or("Client");
    let assessor = data.assessor_name.as_deref().unwrap_or("Security Team");

    format!(
        r#"
<div class="cover-page">
    <div class="classification">{}</div>
    <div class="shield-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="M9 12l2 2 4-4"></path>
        </svg>
    </div>
    <h1 class="report-title">{}</h1>
    <p class="subtitle">Compliance Assessment Report</p>
    <div class="cover-meta">
        <p><strong>Prepared for:</strong> {}</p>
        <p><strong>Prepared by:</strong> {}</p>
        <p><strong>Assessment Date:</strong> {}</p>
        <p><strong>Report Generated:</strong> {}</p>
    </div>
    <div class="cover-summary">
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Frameworks Assessed</span>
        </div>
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Total Findings</span>
        </div>
        <div class="summary-stat score-{} ">
            <span class="stat-value">{:.0}%</span>
            <span class="stat-label">Overall Score</span>
        </div>
    </div>
</div>
"#,
        html_escape(classification),
        html_escape(&data.name),
        html_escape(company),
        html_escape(assessor),
        data.scan_date.format("%Y-%m-%d"),
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        data.summary.frameworks.len(),
        data.summary.total_findings,
        get_score_class(data.summary.overall_score),
        data.summary.overall_score
    )
}

fn generate_executive_summary(data: &ComplianceReportData) -> String {
    let score_class = get_score_class(data.summary.overall_score);
    let score_label = get_score_label(data.summary.overall_score);

    format!(
        r#"
<div class="section" id="executive-summary">
    <h2>Executive Summary</h2>

    <p>This compliance assessment report presents the results of an automated security scan conducted on
    <strong>{}</strong> against {} industry compliance framework(s).</p>

    <div class="score-summary">
        <div class="score-badge score-{}">
            <span class="score-value">{:.0}%</span>
            <span class="score-label">{}</span>
        </div>
        <div class="findings-breakdown">
            <div class="finding-stat critical">
                <span class="value">{}</span>
                <span class="label">Critical</span>
            </div>
            <div class="finding-stat high">
                <span class="value">{}</span>
                <span class="label">High</span>
            </div>
            <div class="finding-stat medium">
                <span class="value">{}</span>
                <span class="label">Medium</span>
            </div>
            <div class="finding-stat low">
                <span class="value">{}</span>
                <span class="label">Low</span>
            </div>
        </div>
    </div>

    <h3>Assessment Scope</h3>
    <p>The assessment evaluated compliance against the following frameworks:</p>
    <ul class="framework-list">
        {}
    </ul>

    <h3>Key Findings</h3>
    <ul class="key-findings">
        <li>Total compliance findings identified: <strong>{}</strong></li>
        <li>Critical/high severity findings requiring immediate attention: <strong>{}</strong></li>
        <li>Overall compliance score: <strong class="score-{}">{:.1}%</strong></li>
        <li>Frameworks analyzed: <strong>{}</strong></li>
    </ul>
</div>
"#,
        data.scan_date.format("%B %d, %Y"),
        data.summary.frameworks.len(),
        score_class,
        data.summary.overall_score,
        score_label,
        data.summary.critical_findings,
        data.summary.high_findings,
        data.summary.medium_findings,
        data.summary.low_findings,
        data.summary
            .frameworks
            .iter()
            .map(|fw| format!(
                "<li><strong>{}</strong> - {:.0}% compliant ({} controls assessed)</li>",
                html_escape(&format!("{:?}", fw.framework)),
                fw.compliance_score,
                fw.total_controls
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        data.summary.total_findings,
        data.summary.critical_findings + data.summary.high_findings,
        score_class,
        data.summary.overall_score,
        data.summary.frameworks.len()
    )
}

fn generate_framework_breakdown(data: &ComplianceReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="framework-breakdown">
    <h2>Framework-by-Framework Analysis</h2>
    <p>Detailed breakdown of compliance status for each assessed framework.</p>
"#,
    );

    for fw in &data.summary.frameworks {
        html.push_str(&generate_framework_section(fw));
    }

    html.push_str("</div>");
    html
}

fn generate_framework_section(fw: &FrameworkSummary) -> String {
    let score_class = get_score_class(fw.compliance_score);

    format!(
        r#"
<div class="framework-section">
    <div class="framework-header">
        <h3>{:?}</h3>
        <div class="framework-score score-{}">{:.0}%</div>
    </div>

    <div class="control-stats">
        <div class="stat-grid">
            <div class="stat-box">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Controls</div>
            </div>
            <div class="stat-box compliant">
                <div class="stat-value">{}</div>
                <div class="stat-label">Compliant</div>
            </div>
            <div class="stat-box non-compliant">
                <div class="stat-value">{}</div>
                <div class="stat-label">Non-Compliant</div>
            </div>
            <div class="stat-box partial">
                <div class="stat-value">{}</div>
                <div class="stat-label">Partially Compliant</div>
            </div>
            <div class="stat-box na">
                <div class="stat-value">{}</div>
                <div class="stat-label">Not Applicable</div>
            </div>
            <div class="stat-box not-assessed">
                <div class="stat-value">{}</div>
                <div class="stat-label">Not Assessed</div>
            </div>
        </div>
    </div>

    {}

    {}
</div>
"#,
        fw.framework,
        score_class,
        fw.compliance_score,
        fw.total_controls,
        fw.compliant,
        fw.non_compliant,
        fw.partially_compliant,
        fw.not_applicable,
        fw.not_assessed,
        generate_compliance_chart(fw),
        generate_category_breakdown(&fw.by_category)
    )
}

fn generate_compliance_chart(fw: &FrameworkSummary) -> String {
    let total = fw.total_controls.max(1) as f64;
    let compliant_pct = (fw.compliant as f64 / total * 100.0).round();
    let non_compliant_pct = (fw.non_compliant as f64 / total * 100.0).round();
    let partial_pct = (fw.partially_compliant as f64 / total * 100.0).round();
    let na_pct = (fw.not_applicable as f64 / total * 100.0).round();

    format!(
        r#"
    <div class="compliance-chart">
        <h4>Control Status Distribution</h4>
        <div class="chart-bar">
            <div class="bar-segment compliant" style="width: {}%">
                <span class="bar-label">{} Compliant</span>
            </div>
            <div class="bar-segment non-compliant" style="width: {}%">
                <span class="bar-label">{} Non-Compliant</span>
            </div>
            <div class="bar-segment partial" style="width: {}%">
                <span class="bar-label">{} Partial</span>
            </div>
            <div class="bar-segment na" style="width: {}%">
                <span class="bar-label">{} N/A</span>
            </div>
        </div>
    </div>
"#,
        compliant_pct,
        fw.compliant,
        non_compliant_pct,
        fw.non_compliant,
        partial_pct,
        fw.partially_compliant,
        na_pct,
        fw.not_applicable
    )
}

fn generate_category_breakdown(categories: &[CategorySummary]) -> String {
    if categories.is_empty() {
        return String::new();
    }

    let mut html = String::from(
        r#"
    <div class="category-breakdown">
        <h4>Control Categories</h4>
        <table class="category-table">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Total</th>
                    <th>Compliant</th>
                    <th>Non-Compliant</th>
                    <th>Compliance %</th>
                    <th>Progress</th>
                </tr>
            </thead>
            <tbody>
"#,
    );

    for cat in categories {
        let score_class = get_score_class(cat.percentage);
        html.push_str(&format!(
            r#"
                <tr>
                    <td class="category-name">{}</td>
                    <td>{}</td>
                    <td class="compliant">{}</td>
                    <td class="non-compliant">{}</td>
                    <td class="score-{}">{:.0}%</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill score-{}" style="width: {}%"></div>
                        </div>
                    </td>
                </tr>
"#,
            html_escape(&cat.category),
            cat.total,
            cat.compliant,
            cat.non_compliant,
            score_class,
            cat.percentage,
            score_class,
            cat.percentage
        ));
    }

    html.push_str("            </tbody>\n        </table>\n    </div>");
    html
}

fn generate_remediation_section(data: &ComplianceReportData) -> String {
    let mut recommendations = Vec::new();

    // Generate prioritized remediation recommendations based on findings
    for fw in &data.summary.frameworks {
        if fw.non_compliant > 0 || fw.partially_compliant > 0 {
            let priority = if fw.compliance_score < 60.0 {
                "High"
            } else if fw.compliance_score < 80.0 {
                "Medium"
            } else {
                "Low"
            };

            recommendations.push((
                priority,
                format!("Address {:?} non-compliance issues", fw.framework),
                format!(
                    "Found {} non-compliant and {} partially compliant controls in {:?}. \
                    Focus on critical and high severity findings first to improve compliance score from {:.0}% to target of 80%+.",
                    fw.non_compliant, fw.partially_compliant, fw.framework, fw.compliance_score
                ),
                if fw.compliance_score < 60.0 {
                    "Immediate (1-2 weeks)"
                } else {
                    "Short-term (1 month)"
                },
            ));
        }
    }

    if recommendations.is_empty() {
        return format!(
            r#"
<div class="section" id="remediation">
    <h2>Remediation Recommendations</h2>
    <p class="success-message">No critical remediation actions required. All assessed controls are compliant or not applicable.</p>
</div>
"#
        );
    }

    let mut html = String::from(
        r#"
<div class="section" id="remediation">
    <h2>Remediation Recommendations</h2>
    <p>Prioritized recommendations to address compliance gaps identified during the assessment.</p>

    <div class="recommendations-list">
"#,
    );

    for (i, (priority, title, description, timeline)) in recommendations.iter().enumerate() {
        html.push_str(&format!(
            r#"
        <div class="recommendation-item priority-{}">
            <div class="rec-header">
                <span class="rec-number">#{}</span>
                <span class="rec-priority priority-badge-{}">{} Priority</span>
            </div>
            <h4>{}</h4>
            <p>{}</p>
            <div class="rec-meta">
                <span><strong>Timeline:</strong> {}</span>
            </div>
        </div>
"#,
            priority.to_lowercase(),
            i + 1,
            priority.to_lowercase(),
            priority,
            html_escape(title),
            html_escape(description),
            timeline
        ));
    }

    html.push_str("    </div>\n</div>");
    html
}

fn generate_appendix(data: &ComplianceReportData) -> String {
    format!(
        r#"
<div class="section" id="appendix">
    <h2>Appendix</h2>

    <h3>A. Assessment Methodology</h3>
    <p>This compliance assessment was conducted using HeroForge, an automated network reconnaissance
    and compliance assessment tool. The assessment methodology included:</p>
    <ul>
        <li>Automated network scanning and vulnerability detection</li>
        <li>Mapping discovered vulnerabilities to compliance framework controls</li>
        <li>Direct compliance-specific checks for configuration and security settings</li>
        <li>Risk scoring and compliance percentage calculation</li>
        <li>Evidence collection and documentation</li>
    </ul>

    <h3>B. Assessment Details</h3>
    <table class="info-table">
        <tr><th>Scan ID</th><td>{}</td></tr>
        <tr><th>Scan Name</th><td>{}</td></tr>
        <tr><th>Assessment Date</th><td>{}</td></tr>
        <tr><th>Frameworks</th><td>{}</td></tr>
        <tr><th>Total Findings</th><td>{}</td></tr>
        <tr><th>Report Generated</th><td>{}</td></tr>
    </table>

    <h3>C. Compliance Frameworks Reference</h3>
    <ul>
        {}
    </ul>

    <h3>D. Disclaimer</h3>
    <p class="disclaimer">This compliance assessment report is based on automated scanning and analysis
    conducted at a specific point in time. While the assessment provides valuable insights into compliance
    status, it should be supplemented with manual reviews, policy assessments, and ongoing monitoring.
    Compliance is an ongoing process that requires continuous attention and improvement. This report is
    intended for authorized security testing and compliance assessment purposes only.</p>
</div>
"#,
        data.scan_id,
        html_escape(&data.scan_name),
        data.scan_date.format("%Y-%m-%d %H:%M UTC"),
        data.summary.frameworks.len(),
        data.summary.total_findings,
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        data.summary
            .frameworks
            .iter()
            .map(|fw| {
                let framework = fw.framework;
                format!(
                    "<li><strong>{}</strong>: {} (Version {})</li>",
                    framework.name(),
                    framework.description(),
                    framework.version()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn generate_footer(data: &ComplianceReportData) -> String {
    format!(
        r#"
<footer class="report-footer">
    <p>Generated by HeroForge Security Assessment Tool</p>
    <p>Report ID: {} | Generated: {}</p>
    <p class="disclaimer">For authorized security testing and compliance assessment only.</p>
</footer>
"#,
        data.id,
        data.created_at.format("%Y-%m-%d %H:%M UTC")
    )
}

fn get_score_class(score: f32) -> &'static str {
    if score >= 80.0 {
        "high"
    } else if score >= 60.0 {
        "medium"
    } else {
        "low"
    }
}

fn get_score_label(score: f32) -> &'static str {
    if score >= 80.0 {
        "Good Compliance"
    } else if score >= 60.0 {
        "Moderate Compliance"
    } else {
        "Poor Compliance"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn get_compliance_css() -> &'static str {
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
    display: block;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 5px;
}

/* Findings breakdown */
.findings-breakdown {
    display: flex;
    gap: 25px;
    flex-wrap: wrap;
}
.finding-stat {
    padding: 15px 25px;
    border-radius: 8px;
    text-align: center;
    min-width: 100px;
}
.finding-stat.critical {
    background: #fef2f2;
    border: 2px solid #dc2626;
}
.finding-stat.high {
    background: #fff7ed;
    border: 2px solid #ea580c;
}
.finding-stat.medium {
    background: #fefce8;
    border: 2px solid #ca8a04;
}
.finding-stat.low {
    background: #eff6ff;
    border: 2px solid #2563eb;
}
.finding-stat .value {
    display: block;
    font-size: 2rem;
    font-weight: bold;
}
.finding-stat.critical .value { color: #dc2626; }
.finding-stat.high .value { color: #ea580c; }
.finding-stat.medium .value { color: #ca8a04; }
.finding-stat.low .value { color: #2563eb; }
.finding-stat .label {
    display: block;
    font-size: 0.85rem;
    color: #64748b;
    text-transform: uppercase;
    margin-top: 5px;
}

/* Framework lists */
.framework-list {
    list-style: none;
    padding: 0;
}
.framework-list li {
    padding: 10px 15px;
    background: #f8fafc;
    border-left: 4px solid #3b82f6;
    margin: 8px 0;
}
.key-findings {
    list-style: disc;
    margin-left: 30px;
}
.key-findings li {
    margin: 8px 0;
}
.key-findings .score-high { color: #22c55e; font-weight: bold; }
.key-findings .score-medium { color: #eab308; font-weight: bold; }
.key-findings .score-low { color: #ef4444; font-weight: bold; }

/* Framework sections */
.framework-section {
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    padding: 25px;
    margin: 25px 0;
    page-break-inside: avoid;
}
.framework-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid #e2e8f0;
}
.framework-header h3 {
    margin: 0;
    color: #1e3a5f;
}
.framework-score {
    font-size: 2rem;
    font-weight: bold;
    padding: 10px 25px;
    border-radius: 6px;
}
.framework-score.score-high {
    background: #f0fdf4;
    color: #22c55e;
}
.framework-score.score-medium {
    background: #fefce8;
    color: #eab308;
}
.framework-score.score-low {
    background: #fef2f2;
    color: #ef4444;
}

/* Control statistics */
.control-stats {
    margin: 20px 0;
}
.stat-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 15px;
}
.stat-box {
    text-align: center;
    padding: 15px;
    border-radius: 6px;
    border: 2px solid #e2e8f0;
    background: #f8fafc;
}
.stat-box.compliant {
    border-color: #22c55e;
    background: #f0fdf4;
}
.stat-box.non-compliant {
    border-color: #ef4444;
    background: #fef2f2;
}
.stat-box.partial {
    border-color: #eab308;
    background: #fefce8;
}
.stat-box.na {
    border-color: #94a3b8;
    background: #f1f5f9;
}
.stat-box.not-assessed {
    border-color: #cbd5e1;
    background: #f8fafc;
}
.stat-box .stat-value {
    font-size: 1.8rem;
    font-weight: bold;
    color: #1e3a5f;
}
.stat-box.compliant .stat-value { color: #22c55e; }
.stat-box.non-compliant .stat-value { color: #ef4444; }
.stat-box.partial .stat-value { color: #eab308; }
.stat-box .stat-label {
    font-size: 0.75rem;
    color: #64748b;
}

/* Compliance chart */
.compliance-chart {
    margin: 25px 0;
    padding: 20px;
    background: #f8fafc;
    border-radius: 6px;
}
.chart-bar {
    display: flex;
    height: 40px;
    border-radius: 4px;
    overflow: hidden;
    margin-top: 15px;
}
.bar-segment {
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-weight: bold;
    font-size: 0.85rem;
    transition: all 0.3s;
}
.bar-segment.compliant { background: #22c55e; }
.bar-segment.non-compliant { background: #ef4444; }
.bar-segment.partial { background: #eab308; }
.bar-segment.na { background: #94a3b8; }

/* Category breakdown */
.category-breakdown {
    margin: 25px 0;
}
.category-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}
.category-table th,
.category-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
}
.category-table th {
    background: #f1f5f9;
    font-weight: 600;
    color: #334155;
}
.category-table .category-name {
    font-weight: 500;
}
.category-table .compliant {
    color: #22c55e;
    font-weight: 600;
}
.category-table .non-compliant {
    color: #ef4444;
    font-weight: 600;
}
.category-table .score-high { color: #22c55e; font-weight: bold; }
.category-table .score-medium { color: #eab308; font-weight: bold; }
.category-table .score-low { color: #ef4444; font-weight: bold; }

/* Progress bar */
.progress-bar {
    width: 100%;
    height: 8px;
    background: #e2e8f0;
    border-radius: 4px;
    overflow: hidden;
}
.progress-fill {
    height: 100%;
    transition: width 0.3s;
}
.progress-fill.score-high { background: #22c55e; }
.progress-fill.score-medium { background: #eab308; }
.progress-fill.score-low { background: #ef4444; }

/* Remediation */
.recommendations-list {
    margin: 20px 0;
}
.recommendation-item {
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    margin: 15px 0;
    page-break-inside: avoid;
}
.recommendation-item.priority-high {
    border-color: #ef4444;
    background: #fef2f2;
}
.recommendation-item.priority-medium {
    border-color: #eab308;
    background: #fefce8;
}
.recommendation-item.priority-low {
    border-color: #3b82f6;
    background: #eff6ff;
}
.rec-header {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-bottom: 15px;
}
.rec-number {
    background: #1e3a5f;
    color: white;
    width: 35px;
    height: 35px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
}
.priority-badge-high {
    background: #ef4444;
    color: white;
    padding: 5px 15px;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: bold;
    text-transform: uppercase;
}
.priority-badge-medium {
    background: #eab308;
    color: white;
    padding: 5px 15px;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: bold;
    text-transform: uppercase;
}
.priority-badge-low {
    background: #3b82f6;
    color: white;
    padding: 5px 15px;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: bold;
    text-transform: uppercase;
}
.rec-meta {
    margin-top: 15px;
    padding-top: 15px;
    border-top: 1px solid #e2e8f0;
    color: #64748b;
    font-size: 0.9rem;
}

/* Info table */
.info-table {
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0;
}
.info-table th,
.info-table td {
    padding: 12px;
    border: 1px solid #e2e8f0;
    text-align: left;
}
.info-table th {
    background: #f1f5f9;
    font-weight: 600;
    width: 30%;
}

/* Success message */
.success-message {
    background: #f0fdf4;
    border: 2px solid #22c55e;
    padding: 20px;
    border-radius: 8px;
    color: #166534;
    font-weight: 500;
}

/* Disclaimer */
.disclaimer {
    background: #fef3c7;
    border: 1px solid #f59e0b;
    padding: 15px;
    border-radius: 4px;
    margin: 20px 0;
    font-size: 0.9rem;
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

/* Print styles */
@media print {
    body { padding: 0; }
    .cover-page { page-break-after: always; }
    .section { page-break-inside: avoid; }
    .framework-section { break-inside: avoid; }
    .recommendation-item { break-inside: avoid; }
}
"#
}
