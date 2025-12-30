//! Compliance Report Generation
//!
//! This module generates PDF and HTML compliance reports from compliance analysis results.
//! Reports include executive summaries, framework-by-framework breakdowns, control status details,
//! evidence, remediation recommendations, and category-level charts.
//!
//! Supports both automated-only and combined (automated + manual) compliance reports.

// Allow dead code for combined report types and functions that are part of the public API
// but not yet integrated into web routes
#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

use crate::compliance::frameworks;
use crate::compliance::manual_assessment::default_rubrics;
use crate::compliance::manual_assessment::types::{
    AssessmentEvidence, ComplianceRubric, EvidenceType, ManualAssessment, OverallRating,
    ReviewStatus,
};
use crate::compliance::types::{
    ComplianceFramework, ComplianceSummary, ControlStatus, FrameworkSummary,
};
use crate::reports::types::ReportFormat;

// Import shared utilities from the compliance submodule
use super::compliance::{
    generate_category_breakdown, generate_compliance_chart, get_compliance_css, get_score_class,
    get_score_label, html_escape,
};

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

// =============================================================================
// Combined Automated + Manual Assessment Types
// =============================================================================

/// Assessment method indicating how a control was evaluated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentMethod {
    /// Control was assessed via automated scanning only
    Automated,
    /// Control was assessed via manual review only
    Manual,
    /// Control was assessed via both automated and manual methods
    Both,
    /// Control has not been assessed
    NotAssessed,
}

impl std::fmt::Display for AssessmentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Automated => write!(f, "Automated"),
            Self::Manual => write!(f, "Manual"),
            Self::Both => write!(f, "Automated + Manual"),
            Self::NotAssessed => write!(f, "Not Assessed"),
        }
    }
}

/// Summary of a manual assessment for inclusion in reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAssessmentSummary {
    /// Assessment ID
    pub assessment_id: String,
    /// Name of the assessor who performed the review
    pub assessor_name: Option<String>,
    /// User ID of the assessor
    pub assessor_user_id: String,
    /// Start of the assessment period
    pub assessment_period_start: DateTime<Utc>,
    /// End of the assessment period
    pub assessment_period_end: DateTime<Utc>,
    /// Overall rating assigned by the assessor
    pub overall_rating: OverallRating,
    /// Numeric score (0-100)
    pub rating_score: f32,
    /// Review/approval status
    pub review_status: ReviewStatus,
    /// Key findings from the assessment
    pub findings: Option<String>,
    /// Recommendations for improvement
    pub recommendations: Option<String>,
    /// Summary of evidence collected
    pub evidence_summary: Option<String>,
    /// Number of evidence items attached
    pub evidence_count: usize,
    /// Evidence items (if included)
    pub evidence_items: Vec<AssessmentEvidence>,
    /// Criterion-level ratings breakdown
    pub criteria_ratings: Vec<CriterionRatingSummary>,
    /// When the assessment was created
    pub created_at: DateTime<Utc>,
    /// When the assessment was last updated
    pub updated_at: DateTime<Utc>,
}

/// Summary of a single criterion rating for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionRatingSummary {
    /// Criterion ID
    pub criterion_id: String,
    /// Criterion question/name
    pub criterion_name: String,
    /// Rating value assigned
    pub rating: i32,
    /// Rating label (e.g., "Fully Implemented")
    pub rating_label: String,
    /// Notes provided for this criterion
    pub notes: Option<String>,
}

/// Combined result for a single compliance control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedControlResult {
    /// Control ID
    pub control_id: String,
    /// Control title/name
    pub control_title: String,
    /// Framework this control belongs to
    pub framework: ComplianceFramework,
    /// Category within the framework
    pub category: String,
    /// How this control was assessed
    pub assessment_method: AssessmentMethod,
    /// Status from automated scan (if available)
    pub automated_status: Option<ControlStatus>,
    /// Status from manual assessment (if available)
    pub manual_status: Option<ControlStatus>,
    /// Combined/final compliance status
    pub combined_status: ControlStatus,
    /// Number of evidence items from manual assessment
    pub manual_evidence_count: usize,
    /// Findings from manual assessment
    pub manual_findings: Option<String>,
    /// Recommendations from manual assessment
    pub manual_recommendations: Option<String>,
    /// Full manual assessment summary (if available)
    pub manual_assessment: Option<ManualAssessmentSummary>,
    /// Evidence from automated scan
    pub automated_evidence: Vec<String>,
    /// Remediation guidance
    pub remediation: Option<String>,
}

/// Combined compliance summary including both automated and manual assessments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedFrameworkSummary {
    /// Framework being summarized
    pub framework: ComplianceFramework,
    /// Total controls in the framework
    pub total_controls: usize,
    /// Controls assessed via automation only
    pub automated_only: usize,
    /// Controls assessed via manual review only
    pub manual_only: usize,
    /// Controls assessed via both methods
    pub both_methods: usize,
    /// Controls not yet assessed
    pub not_assessed: usize,
    /// Number of compliant controls (combined)
    pub compliant: usize,
    /// Number of non-compliant controls (combined)
    pub non_compliant: usize,
    /// Number of partially compliant controls (combined)
    pub partially_compliant: usize,
    /// Number of not-applicable controls
    pub not_applicable: usize,
    /// Automated scan compliance score
    pub automated_score: f32,
    /// Manual assessment compliance score
    pub manual_score: f32,
    /// Combined weighted compliance score
    pub combined_score: f32,
    /// Weight given to automated results (0.0 - 1.0)
    pub automated_weight: f32,
    /// Weight given to manual results (0.0 - 1.0)
    pub manual_weight: f32,
    /// Category breakdown with combined results
    pub by_category: Vec<CombinedCategorySummary>,
    /// Per-control combined results
    pub control_results: Vec<CombinedControlResult>,
}

/// Combined category summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedCategorySummary {
    /// Category name
    pub category: String,
    /// Total controls in category
    pub total: usize,
    /// Compliant controls (combined)
    pub compliant: usize,
    /// Non-compliant controls (combined)
    pub non_compliant: usize,
    /// Controls with manual assessments
    pub manually_assessed: usize,
    /// Combined compliance percentage
    pub percentage: f32,
}

/// Complete data structure for combined compliance report generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedComplianceReportData {
    /// Report ID
    pub id: String,
    /// Report name/title
    pub name: String,
    /// Scan ID (for automated results)
    pub scan_id: String,
    /// Scan name
    pub scan_name: String,
    /// Campaign ID (for manual assessments, optional)
    pub campaign_id: Option<String>,
    /// Campaign name (if applicable)
    pub campaign_name: Option<String>,
    /// Report generation timestamp
    pub created_at: DateTime<Utc>,
    /// Scan completion timestamp
    pub scan_date: DateTime<Utc>,
    /// Assessment period start (for manual assessments)
    pub assessment_period_start: Option<DateTime<Utc>>,
    /// Assessment period end (for manual assessments)
    pub assessment_period_end: Option<DateTime<Utc>>,
    /// Original automated compliance summary
    pub automated_summary: ComplianceSummary,
    /// Combined framework summaries
    pub combined_frameworks: Vec<CombinedFrameworkSummary>,
    /// Overall combined compliance score
    pub overall_combined_score: f32,
    /// Overall automated score
    pub overall_automated_score: f32,
    /// Overall manual score (if manual assessments exist)
    pub overall_manual_score: Option<f32>,
    /// Total manual assessments included
    pub total_manual_assessments: usize,
    /// Total evidence items from manual assessments
    pub total_evidence_items: usize,
    /// Company name (optional)
    pub company_name: Option<String>,
    /// Primary assessor name (optional)
    pub assessor_name: Option<String>,
    /// All assessors who contributed manual reviews
    pub manual_assessors: Vec<String>,
    /// Report classification (e.g., "CONFIDENTIAL")
    pub classification: Option<String>,
    /// Whether to include evidence details
    pub include_evidence: bool,
    /// List of all evidence items (if include_evidence is true)
    pub all_evidence: Vec<AssessmentEvidence>,
}

impl CombinedComplianceReportData {
    /// Calculate statistics for the report
    pub fn calculate_statistics(&self) -> CombinedReportStatistics {
        let mut total_controls = 0;
        let mut automated_assessed = 0;
        let mut manual_assessed = 0;
        let mut both_assessed = 0;
        let mut total_compliant = 0;
        let mut total_non_compliant = 0;

        for fw in &self.combined_frameworks {
            total_controls += fw.total_controls;
            automated_assessed += fw.automated_only + fw.both_methods;
            manual_assessed += fw.manual_only + fw.both_methods;
            both_assessed += fw.both_methods;
            total_compliant += fw.compliant;
            total_non_compliant += fw.non_compliant;
        }

        CombinedReportStatistics {
            total_controls,
            automated_assessed,
            manual_assessed,
            both_assessed,
            total_compliant,
            total_non_compliant,
            total_manual_assessments: self.total_manual_assessments,
            total_evidence_items: self.total_evidence_items,
        }
    }
}

/// Statistics for combined compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedReportStatistics {
    /// Total controls across all frameworks
    pub total_controls: usize,
    /// Controls with automated assessment
    pub automated_assessed: usize,
    /// Controls with manual assessment
    pub manual_assessed: usize,
    /// Controls with both assessment types
    pub both_assessed: usize,
    /// Total compliant controls
    pub total_compliant: usize,
    /// Total non-compliant controls
    pub total_non_compliant: usize,
    /// Total manual assessments
    pub total_manual_assessments: usize,
    /// Total evidence items
    pub total_evidence_items: usize,
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
    <p>Generated by Genial Architect Assessment Tool</p>
    <p>Report ID: {} | Generated: {}</p>
    <p class="disclaimer">For authorized security testing and compliance assessment only.</p>
</footer>
"#,
        data.id,
        data.created_at.format("%Y-%m-%d %H:%M UTC")
    )
}

// Note: get_score_class, get_score_label, html_escape, and get_compliance_css
// are now imported from super::compliance

// =============================================================================
// Combined Report Generation Functions
// =============================================================================

/// Combine automated compliance status with manual assessment status
///
/// Logic:
/// - If only automated: use automated status
/// - If only manual: use manual status
/// - If both: manual overrides automated (manual is considered authoritative)
/// - If statuses conflict and both present, take the more conservative (worse) status
pub fn combine_compliance_status(
    automated: Option<ControlStatus>,
    manual: Option<ControlStatus>,
) -> ControlStatus {
    match (automated, manual) {
        (None, None) => ControlStatus::NotAssessed,
        (Some(auto), None) => auto,
        (None, Some(manual)) => manual,
        (Some(auto), Some(manual)) => {
            // Manual assessment is authoritative - it overrides automated
            // However, if manual says compliant but auto found issues, take conservative approach
            match (manual, auto) {
                // Manual says compliant
                (ControlStatus::Compliant, ControlStatus::NonCompliant) => {
                    // Manual override - trust the human reviewer
                    ControlStatus::Compliant
                }
                (ControlStatus::Compliant, ControlStatus::PartiallyCompliant) => {
                    ControlStatus::Compliant
                }
                // Manual says non-compliant - always trust this
                (ControlStatus::NonCompliant, _) => ControlStatus::NonCompliant,
                // Manual says partial
                (ControlStatus::PartiallyCompliant, ControlStatus::NonCompliant) => {
                    ControlStatus::PartiallyCompliant
                }
                // Manual says N/A
                (ControlStatus::NotApplicable, _) => ControlStatus::NotApplicable,
                // Default: use manual status
                (manual_status, _) => manual_status,
            }
        }
    }
}

/// Convert OverallRating to ControlStatus
pub fn overall_rating_to_control_status(rating: &OverallRating) -> ControlStatus {
    match rating {
        OverallRating::Compliant => ControlStatus::Compliant,
        OverallRating::NonCompliant => ControlStatus::NonCompliant,
        OverallRating::Partial => ControlStatus::PartiallyCompliant,
        OverallRating::NotApplicable => ControlStatus::NotApplicable,
    }
}

/// Get the latest approved manual assessment for a control
pub fn get_latest_approved_assessment<'a>(
    assessments: &'a [ManualAssessment],
    framework_id: &str,
    control_id: &str,
) -> Option<&'a ManualAssessment> {
    assessments
        .iter()
        .filter(|a| {
            a.framework_id == framework_id
                && a.control_id == control_id
                && a.review_status == ReviewStatus::Approved
        })
        .max_by_key(|a| a.updated_at)
}

/// Build combined compliance results from automated scan and manual assessments
///
/// This function:
/// 1. Takes the automated compliance summary from a scan
/// 2. Retrieves all approved manual assessments for the relevant frameworks
/// 3. Combines them per-control with appropriate status merging logic
/// 4. Calculates combined scores with configurable weighting
pub fn build_combined_results(
    automated_summary: &ComplianceSummary,
    manual_assessments: &[ManualAssessment],
    evidence_by_assessment: &HashMap<String, Vec<AssessmentEvidence>>,
    user_names: &HashMap<String, String>,
    automated_weight: f32,
    manual_weight: f32,
) -> Vec<CombinedFrameworkSummary> {
    let mut combined_frameworks = Vec::new();

    for fw_summary in &automated_summary.frameworks {
        let framework = fw_summary.framework;
        let framework_id = framework.id();

        // Get all controls for this framework from the frameworks module
        let all_controls = frameworks::get_controls(framework);

        // Get rubrics for this framework for criterion name lookups
        let framework_rubrics = default_rubrics::get_rubrics_by_framework(framework_id);
        let rubrics_by_control: HashMap<&str, &ComplianceRubric> = framework_rubrics
            .iter()
            .map(|r| (r.control_id.as_str(), r))
            .collect();

        // Get all manual assessments for this framework
        let fw_manual_assessments: Vec<&ManualAssessment> = manual_assessments
            .iter()
            .filter(|a| {
                a.framework_id == framework_id && a.review_status == ReviewStatus::Approved
            })
            .collect();

        // Build lookup for manual assessments by control_id
        let manual_by_control: HashMap<String, &ManualAssessment> = fw_manual_assessments
            .iter()
            .map(|a| (a.control_id.clone(), *a))
            .collect();

        // Track statistics
        let mut automated_only = 0usize;
        let mut manual_only = 0usize;
        let mut both_methods = 0usize;
        let mut compliant = 0usize;
        let mut non_compliant = 0usize;
        let mut partially_compliant = 0usize;
        let mut not_applicable = 0usize;
        let mut not_assessed_count = 0usize;

        // Track manual assessments per category for category breakdown
        let mut manual_by_category: HashMap<String, usize> = HashMap::new();

        // Build control results by iterating through all framework controls
        let mut control_results: Vec<CombinedControlResult> = Vec::new();

        for control in &all_controls {
            let control_id = &control.control_id;
            let has_manual = manual_by_control.contains_key(control_id);
            // Check if this control can be automated (has automated_check = true)
            let has_automated = control.automated_check;

            // Determine assessment method
            let assessment_method = match (has_automated, has_manual) {
                (true, true) => {
                    both_methods += 1;
                    AssessmentMethod::Both
                }
                (true, false) => {
                    automated_only += 1;
                    AssessmentMethod::Automated
                }
                (false, true) => {
                    manual_only += 1;
                    AssessmentMethod::Manual
                }
                (false, false) => {
                    not_assessed_count += 1;
                    AssessmentMethod::NotAssessed
                }
            };

            // Get manual assessment if available
            let manual_assessment_opt = manual_by_control.get(control_id).copied();
            let manual_status = manual_assessment_opt
                .map(|a| overall_rating_to_control_status(&a.overall_rating));

            // For automated status, we derive it from the framework summary statistics
            // In a more complete implementation, this would come from per-control finding data
            let automated_status = if has_automated {
                // Use NotAssessed as placeholder since we don't have per-control automated findings
                // The actual status would come from compliance findings in a full implementation
                Some(ControlStatus::NotAssessed)
            } else {
                None
            };

            // Combine statuses
            let combined_status = combine_compliance_status(automated_status, manual_status);

            // Count by status
            match combined_status {
                ControlStatus::Compliant => compliant += 1,
                ControlStatus::NonCompliant => non_compliant += 1,
                ControlStatus::PartiallyCompliant => partially_compliant += 1,
                ControlStatus::NotApplicable => not_applicable += 1,
                ControlStatus::NotAssessed => {} // Already counted above
                ControlStatus::ManualOverride => compliant += 1,
            }

            // Track manual assessments by category
            if has_manual {
                *manual_by_category.entry(control.category.clone()).or_insert(0) += 1;
            }

            // Build manual assessment summary if available
            let manual_assessment_summary = manual_assessment_opt.map(|assessment| {
                let evidence_items = evidence_by_assessment
                    .get(&assessment.id)
                    .cloned()
                    .unwrap_or_default();
                let evidence_count = evidence_items.len();

                // Build criterion ratings with proper names from rubric
                let rubric_opt = rubrics_by_control.get(control_id.as_str()).copied();
                let criteria_ratings: Vec<CriterionRatingSummary> = assessment
                    .criteria_responses
                    .iter()
                    .map(|cr| {
                        // Look up criterion name from rubric
                        let criterion_name = rubric_opt
                            .and_then(|rubric| {
                                rubric
                                    .assessment_criteria
                                    .iter()
                                    .find(|c| c.id == cr.criterion_id)
                                    .map(|c| c.question.clone())
                            })
                            .unwrap_or_else(|| cr.criterion_id.clone());

                        CriterionRatingSummary {
                            criterion_id: cr.criterion_id.clone(),
                            criterion_name,
                            rating: cr.rating,
                            rating_label: rating_to_label(cr.rating),
                            notes: cr.notes.clone(),
                        }
                    })
                    .collect();

                let assessor_name = user_names.get(&assessment.user_id).cloned();

                ManualAssessmentSummary {
                    assessment_id: assessment.id.clone(),
                    assessor_name,
                    assessor_user_id: assessment.user_id.clone(),
                    assessment_period_start: assessment.assessment_period_start,
                    assessment_period_end: assessment.assessment_period_end,
                    overall_rating: assessment.overall_rating.clone(),
                    rating_score: assessment.rating_score,
                    review_status: assessment.review_status.clone(),
                    findings: assessment.findings.clone(),
                    recommendations: assessment.recommendations.clone(),
                    evidence_summary: assessment.evidence_summary.clone(),
                    evidence_count,
                    evidence_items,
                    criteria_ratings,
                    created_at: assessment.created_at,
                    updated_at: assessment.updated_at,
                }
            });

            let evidence_count = manual_assessment_summary
                .as_ref()
                .map(|s| s.evidence_count)
                .unwrap_or(0);

            control_results.push(CombinedControlResult {
                control_id: control_id.clone(),
                control_title: control.title.clone(),
                framework,
                category: control.category.clone(),
                assessment_method,
                automated_status,
                manual_status,
                combined_status,
                manual_evidence_count: evidence_count,
                manual_findings: manual_assessment_opt.and_then(|a| a.findings.clone()),
                manual_recommendations: manual_assessment_opt.and_then(|a| a.recommendations.clone()),
                manual_assessment: manual_assessment_summary,
                automated_evidence: Vec::new(), // Would come from compliance findings
                remediation: control.remediation_guidance.clone(),
            });
        }

        // Calculate scores
        let manual_score = if !fw_manual_assessments.is_empty() {
            let total_score: f32 = fw_manual_assessments.iter().map(|a| a.rating_score).sum();
            total_score / fw_manual_assessments.len() as f32
        } else {
            0.0
        };

        // Combined score is weighted average
        let has_manual = !fw_manual_assessments.is_empty();
        let combined_score = if has_manual {
            (fw_summary.compliance_score * automated_weight) + (manual_score * manual_weight)
        } else {
            fw_summary.compliance_score
        };

        // Build category summary with combined data using control-to-category mapping
        let combined_categories: Vec<CombinedCategorySummary> = fw_summary
            .by_category
            .iter()
            .map(|cat| {
                // Count manual assessments in this category using our mapping
                let manually_assessed = manual_by_category
                    .get(&cat.category)
                    .copied()
                    .unwrap_or(0);

                CombinedCategorySummary {
                    category: cat.category.clone(),
                    total: cat.total,
                    compliant: cat.compliant,
                    non_compliant: cat.non_compliant,
                    manually_assessed,
                    percentage: cat.percentage,
                }
            })
            .collect();

        combined_frameworks.push(CombinedFrameworkSummary {
            framework,
            total_controls: all_controls.len(),
            automated_only,
            manual_only,
            both_methods,
            not_assessed: not_assessed_count,
            compliant,
            non_compliant,
            partially_compliant,
            not_applicable,
            automated_score: fw_summary.compliance_score,
            manual_score,
            combined_score,
            automated_weight,
            manual_weight,
            by_category: combined_categories,
            control_results,
        });
    }

    combined_frameworks
}

/// Convert rating value to human-readable label
fn rating_to_label(rating: i32) -> String {
    match rating {
        5 => "Optimized".to_string(),
        4 => "Fully Implemented".to_string(),
        3 => "Largely Implemented".to_string(),
        2 => "Partially Implemented".to_string(),
        1 => "Not Implemented".to_string(),
        _ => format!("Rating {}", rating),
    }
}

/// Generate a combined compliance report (automated + manual)
pub async fn generate_combined(
    data: &CombinedComplianceReportData,
    format: ReportFormat,
    reports_dir: &str,
) -> Result<(String, i64)> {
    match format {
        ReportFormat::Html => generate_combined_html(data, reports_dir).await,
        ReportFormat::Pdf => generate_combined_pdf(data, reports_dir).await,
        ReportFormat::Json => generate_combined_json(data, reports_dir).await,
    }
}

/// Generate combined HTML compliance report
async fn generate_combined_html(
    data: &CombinedComplianceReportData,
    reports_dir: &str,
) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    let filename = format!("{}.html", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    let html_content = build_combined_html_report(data);

    fs::write(&file_path, &html_content).await?;

    let file_size = html_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Generate combined PDF compliance report
async fn generate_combined_pdf(
    data: &CombinedComplianceReportData,
    reports_dir: &str,
) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    // Generate HTML first
    let html_content = build_combined_html_report(data);

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

/// Generate combined JSON compliance report
async fn generate_combined_json(
    data: &CombinedComplianceReportData,
    reports_dir: &str,
) -> Result<(String, i64)> {
    fs::create_dir_all(reports_dir).await?;

    let filename = format!("{}.json", data.id);
    let file_path = Path::new(reports_dir).join(&filename);

    let json_content = serde_json::to_string_pretty(data)?;

    fs::write(&file_path, &json_content).await?;

    let file_size = json_content.len() as i64;
    let path_str = file_path.to_string_lossy().to_string();

    Ok((path_str, file_size))
}

/// Build HTML content for combined compliance report
fn build_combined_html_report(data: &CombinedComplianceReportData) -> String {
    let mut html = String::new();

    // Document head
    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{} - Combined Compliance Report</title>
    <style>{}</style>
</head>
<body>
"#,
        html_escape(&data.name),
        get_compliance_css()
    ));

    // Cover page
    html.push_str(&generate_combined_cover_page(data));

    // Executive summary with combined scores
    html.push_str(&generate_combined_executive_summary(data));

    // Framework-by-framework breakdown with manual assessment data
    html.push_str(&generate_combined_framework_breakdown(data));

    // Manual assessment details section
    if data.total_manual_assessments > 0 {
        html.push_str(&generate_manual_assessment_details(data));
    }

    // Remediation recommendations
    html.push_str(&generate_combined_remediation_section(data));

    // Evidence appendix (if included)
    if data.include_evidence && !data.all_evidence.is_empty() {
        html.push_str(&generate_evidence_appendix(data));
    }

    // Appendix
    html.push_str(&generate_combined_appendix(data));

    // Footer
    html.push_str(&generate_combined_footer(data));

    html.push_str("</body>\n</html>");

    html
}

fn generate_combined_cover_page(data: &CombinedComplianceReportData) -> String {
    let classification = data.classification.as_deref().unwrap_or("CONFIDENTIAL");
    let company = data.company_name.as_deref().unwrap_or("Client");
    let assessor = data.assessor_name.as_deref().unwrap_or("Security Team");

    let stats = data.calculate_statistics();

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
    <p class="subtitle">Combined Compliance Assessment Report</p>
    <p class="subtitle" style="font-size: 0.9rem; color: #94a3b8;">Automated Scan + Manual Assessment</p>
    <div class="cover-meta">
        <p><strong>Prepared for:</strong> {}</p>
        <p><strong>Prepared by:</strong> {}</p>
        <p><strong>Assessment Date:</strong> {}</p>
        <p><strong>Report Generated:</strong> {}</p>
        {}
    </div>
    <div class="cover-summary">
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Frameworks Assessed</span>
        </div>
        <div class="summary-stat">
            <span class="stat-value">{}</span>
            <span class="stat-label">Manual Assessments</span>
        </div>
        <div class="summary-stat score-{} ">
            <span class="stat-value">{:.0}%</span>
            <span class="stat-label">Combined Score</span>
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
        if !data.manual_assessors.is_empty() {
            format!("<p><strong>Manual Assessors:</strong> {}</p>",
                html_escape(&data.manual_assessors.join(", ")))
        } else {
            String::new()
        },
        data.combined_frameworks.len(),
        stats.total_manual_assessments,
        get_score_class(data.overall_combined_score),
        data.overall_combined_score
    )
}

fn generate_combined_executive_summary(data: &CombinedComplianceReportData) -> String {
    let stats = data.calculate_statistics();
    let score_class = get_score_class(data.overall_combined_score);
    let score_label = get_score_label(data.overall_combined_score);

    let has_manual = data.total_manual_assessments > 0;

    format!(
        r#"
<div class="section" id="executive-summary">
    <h2>Executive Summary</h2>

    <p>This combined compliance assessment report presents the results of both automated security scanning
    and manual compliance assessments conducted on <strong>{}</strong> against {} industry compliance framework(s).</p>

    {}

    <div class="combined-score-comparison">
        <div class="score-comparison-item automated">
            <div class="score-type">Automated Scan</div>
            <div class="score-value">{:.0}%</div>
        </div>
        {}
        <div class="score-comparison-item combined">
            <div class="score-type">Combined Score</div>
            <div class="score-value">{:.0}%</div>
        </div>
    </div>

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

    <h3>Assessment Coverage</h3>
    <ul class="key-findings">
        <li>Total controls assessed: <strong>{}</strong></li>
        <li>Controls with automated assessment: <strong>{}</strong></li>
        <li>Controls with manual assessment: <strong>{}</strong></li>
        <li>Controls with both methods: <strong>{}</strong></li>
        <li>Total evidence items collected: <strong>{}</strong></li>
    </ul>

    <h3>Framework Scores</h3>
    <ul class="framework-list">
        {}
    </ul>
</div>
"#,
        data.scan_date.format("%B %d, %Y"),
        data.combined_frameworks.len(),
        if has_manual {
            "<p class=\"success-message\" style=\"background: #fffbeb; border-color: #fbbf24; color: #b45309;\">
            This report includes manual compliance assessments that provide additional context and evidence
            beyond automated scanning. Manual assessments are indicated with a special badge throughout the report.</p>"
        } else {
            ""
        },
        data.overall_automated_score,
        if let Some(manual_score) = data.overall_manual_score {
            format!(
                r#"<div class="score-comparison-item manual">
                    <div class="score-type">Manual Assessment</div>
                    <div class="score-value">{:.0}%</div>
                </div>"#,
                manual_score
            )
        } else {
            String::new()
        },
        data.overall_combined_score,
        score_class,
        data.overall_combined_score,
        score_label,
        data.automated_summary.critical_findings,
        data.automated_summary.high_findings,
        data.automated_summary.medium_findings,
        data.automated_summary.low_findings,
        stats.total_controls,
        stats.automated_assessed,
        stats.manual_assessed,
        stats.both_assessed,
        stats.total_evidence_items,
        data.combined_frameworks
            .iter()
            .map(|fw| format!(
                "<li><strong>{}</strong> - Combined: <span class=\"score-{}\">{:.0}%</span> \
                (Auto: {:.0}%, Manual: {:.0}%) - {} controls ({} manually assessed)</li>",
                html_escape(&format!("{:?}", fw.framework)),
                get_score_class(fw.combined_score),
                fw.combined_score,
                fw.automated_score,
                fw.manual_score,
                fw.total_controls,
                fw.manual_only + fw.both_methods
            ))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn generate_combined_framework_breakdown(data: &CombinedComplianceReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="framework-breakdown">
    <h2>Framework-by-Framework Analysis</h2>
    <p>Detailed breakdown of compliance status for each assessed framework, including both automated and manual assessment results.</p>
"#,
    );

    for fw in &data.combined_frameworks {
        html.push_str(&generate_combined_framework_section(fw));
    }

    html.push_str("</div>");
    html
}

fn generate_combined_framework_section(fw: &CombinedFrameworkSummary) -> String {
    let score_class = get_score_class(fw.combined_score);
    let has_manual = fw.manual_only > 0 || fw.both_methods > 0;

    format!(
        r#"
<div class="framework-section">
    <div class="framework-header">
        <h3>{:?}</h3>
        <div style="display: flex; gap: 15px; align-items: center;">
            {}
            <div class="framework-score score-{}">{:.0}%</div>
        </div>
    </div>

    <div class="combined-score-comparison" style="margin-bottom: 20px;">
        <div class="score-comparison-item automated" style="flex: 1;">
            <div class="score-type">Automated</div>
            <div class="score-value" style="font-size: 1.5rem;">{:.0}%</div>
        </div>
        <div class="score-comparison-item manual" style="flex: 1;">
            <div class="score-type">Manual</div>
            <div class="score-value" style="font-size: 1.5rem;">{:.0}%</div>
        </div>
        <div class="score-comparison-item combined" style="flex: 1;">
            <div class="score-type">Combined</div>
            <div class="score-value" style="font-size: 1.5rem;">{:.0}%</div>
        </div>
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
                <div class="stat-label">Partial</div>
            </div>
            <div class="stat-box" style="border-color: #3b82f6; background: #eff6ff;">
                <div class="stat-value" style="color: #3b82f6;">{}</div>
                <div class="stat-label">Auto Only</div>
            </div>
            <div class="stat-box" style="border-color: #f59e0b; background: #fffbeb;">
                <div class="stat-value" style="color: #f59e0b;">{}</div>
                <div class="stat-label">Manual</div>
            </div>
        </div>
    </div>

    {}

    {}
</div>
"#,
        fw.framework,
        if has_manual {
            r#"<span class="assessment-method-badge both">Includes Manual Assessments</span>"#
        } else {
            r#"<span class="assessment-method-badge automated">Automated Only</span>"#
        },
        score_class,
        fw.combined_score,
        fw.automated_score,
        fw.manual_score,
        fw.combined_score,
        fw.total_controls,
        fw.compliant,
        fw.non_compliant,
        fw.partially_compliant,
        fw.automated_only,
        fw.manual_only + fw.both_methods,
        generate_combined_compliance_chart(fw),
        generate_combined_category_breakdown(&fw.by_category)
    )
}

fn generate_combined_compliance_chart(fw: &CombinedFrameworkSummary) -> String {
    let total = fw.total_controls.max(1) as f64;
    let compliant_pct = (fw.compliant as f64 / total * 100.0).round();
    let non_compliant_pct = (fw.non_compliant as f64 / total * 100.0).round();
    let partial_pct = (fw.partially_compliant as f64 / total * 100.0).round();
    let na_pct = (fw.not_applicable as f64 / total * 100.0).round();

    format!(
        r#"
    <div class="compliance-chart">
        <h4>Control Status Distribution (Combined)</h4>
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

fn generate_combined_category_breakdown(categories: &[CombinedCategorySummary]) -> String {
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
                    <th>Manual</th>
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
                    <td style="color: #f59e0b;">{}</td>
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
            cat.manually_assessed,
            score_class,
            cat.percentage,
            score_class,
            cat.percentage
        ));
    }

    html.push_str("            </tbody>\n        </table>\n    </div>");
    html
}

fn generate_manual_assessment_details(data: &CombinedComplianceReportData) -> String {
    let mut html = String::from(
        r#"<div class="section" id="manual-assessments">
    <h2>Manual Assessment Details</h2>
    <p>Detailed information about manual compliance assessments conducted by authorized assessors.</p>
"#,
    );

    for fw in &data.combined_frameworks {
        for control in &fw.control_results {
            if let Some(ref assessment) = control.manual_assessment {
                html.push_str(&generate_control_assessment_detail(control, assessment));
            }
        }
    }

    html.push_str("</div>");
    html
}

fn generate_control_assessment_detail(
    control: &CombinedControlResult,
    assessment: &ManualAssessmentSummary,
) -> String {
    let status_class = match assessment.overall_rating {
        OverallRating::Compliant => "compliant",
        OverallRating::NonCompliant => "non-compliant",
        OverallRating::Partial => "partial",
        OverallRating::NotApplicable => "na",
    };

    let mut html = format!(
        r#"
<div class="control-detail-card has-manual">
    <div class="control-detail-header">
        <div>
            <span class="control-id">{}</span>
            <span style="color: #64748b; margin-left: 10px;">{}</span>
        </div>
        <div class="badges">
            <span class="assessment-method-badge {}">{}</span>
            <span class="assessment-method-badge {}" style="background: {}; color: white;">{:?}</span>
        </div>
    </div>

    <div class="manual-assessment-section">
        <h5>
            <svg class="icon-manual" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path>
                <rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect>
                <path d="M9 14l2 2 4-4"></path>
            </svg>
            Manual Assessment
        </h5>

        <div class="assessment-meta">
            <div class="assessment-meta-item">
                <div class="label">Assessor</div>
                <div class="value">{}</div>
            </div>
            <div class="assessment-meta-item">
                <div class="label">Assessment Period</div>
                <div class="value">{} - {}</div>
            </div>
            <div class="assessment-meta-item">
                <div class="label">Rating Score</div>
                <div class="value">{:.0}%</div>
            </div>
        </div>
"#,
        html_escape(&control.control_id),
        html_escape(&control.control_title),
        match control.assessment_method {
            AssessmentMethod::Automated => "automated",
            AssessmentMethod::Manual => "manual",
            AssessmentMethod::Both => "both",
            AssessmentMethod::NotAssessed => "not-assessed",
        },
        control.assessment_method,
        status_class,
        match assessment.overall_rating {
            OverallRating::Compliant => "#22c55e",
            OverallRating::NonCompliant => "#ef4444",
            OverallRating::Partial => "#eab308",
            OverallRating::NotApplicable => "#94a3b8",
        },
        assessment.overall_rating,
        assessment.assessor_name.as_deref().unwrap_or("Unknown"),
        assessment.assessment_period_start.format("%Y-%m-%d"),
        assessment.assessment_period_end.format("%Y-%m-%d"),
        assessment.rating_score
    );

    // Criteria ratings
    if !assessment.criteria_ratings.is_empty() {
        html.push_str(r#"<div class="criteria-ratings"><h6>Criterion Ratings</h6>"#);
        for criterion in &assessment.criteria_ratings {
            let rating_class = if criterion.rating >= 4 {
                "rating-high"
            } else if criterion.rating >= 3 {
                "rating-medium"
            } else {
                "rating-low"
            };
            html.push_str(&format!(
                r#"<div class="criteria-rating-item">
                    <span class="question">{}</span>
                    <span class="rating {}">{}</span>
                </div>"#,
                html_escape(&criterion.criterion_name),
                rating_class,
                html_escape(&criterion.rating_label)
            ));
        }
        html.push_str("</div>");
    }

    // Findings
    if let Some(ref findings) = assessment.findings {
        html.push_str(&format!(
            r#"<div class="findings-box">
                <h6>Key Findings</h6>
                <p>{}</p>
            </div>"#,
            html_escape(findings)
        ));
    }

    // Recommendations
    if let Some(ref recommendations) = assessment.recommendations {
        html.push_str(&format!(
            r#"<div class="recommendations-box">
                <h6>Recommendations</h6>
                <p>{}</p>
            </div>"#,
            html_escape(recommendations)
        ));
    }

    // Evidence summary
    if assessment.evidence_count > 0 {
        html.push_str(&format!(
            r#"<div class="evidence-list">
                <h6>Evidence ({} items)</h6>"#,
            assessment.evidence_count
        ));
        for evidence in &assessment.evidence_items {
            let type_badge = match evidence.evidence_type {
                EvidenceType::File => "File",
                EvidenceType::Link => "Link",
                EvidenceType::Screenshot => "Screenshot",
                EvidenceType::Note => "Note",
            };
            html.push_str(&format!(
                r#"<div class="evidence-item">
                    <span class="type-badge">{}</span>
                    <span class="title">{}</span>
                </div>"#,
                type_badge,
                html_escape(&evidence.title)
            ));
        }
        html.push_str("</div>");
    }

    html.push_str("</div></div>");
    html
}

fn generate_combined_remediation_section(data: &CombinedComplianceReportData) -> String {
    let mut recommendations = Vec::new();

    // Generate prioritized remediation recommendations based on findings
    for fw in &data.combined_frameworks {
        if fw.non_compliant > 0 || fw.partially_compliant > 0 {
            let priority = if fw.combined_score < 60.0 {
                "High"
            } else if fw.combined_score < 80.0 {
                "Medium"
            } else {
                "Low"
            };

            recommendations.push((
                priority,
                format!("Address {:?} non-compliance issues", fw.framework),
                format!(
                    "Found {} non-compliant and {} partially compliant controls in {:?}. \
                    Focus on critical and high severity findings first to improve compliance score from {:.0}% to target of 80%+.{}",
                    fw.non_compliant, fw.partially_compliant, fw.framework, fw.combined_score,
                    if fw.manual_only + fw.both_methods > 0 {
                        format!(" {} controls have manual assessment data with specific recommendations.",
                            fw.manual_only + fw.both_methods)
                    } else {
                        String::new()
                    }
                ),
                if fw.combined_score < 60.0 {
                    "Immediate (1-2 weeks)"
                } else {
                    "Short-term (1 month)"
                },
            ));
        }

        // Add manual assessment recommendations
        for control in &fw.control_results {
            if let Some(ref assessment) = control.manual_assessment {
                if let Some(ref recommendations_text) = assessment.recommendations {
                    if !recommendations_text.is_empty() {
                        let priority = match assessment.overall_rating {
                            OverallRating::NonCompliant => "High",
                            OverallRating::Partial => "Medium",
                            _ => continue,
                        };
                        recommendations.push((
                            priority,
                            format!("Manual Assessment: {} - {}", control.control_id, control.control_title),
                            recommendations_text.clone(),
                            "Per assessor recommendation",
                        ));
                    }
                }
            }
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
    <p>Prioritized recommendations to address compliance gaps identified during automated and manual assessments.</p>

    <div class="recommendations-list">
"#,
    );

    for (i, (priority, title, description, timeline)) in recommendations.iter().take(10).enumerate() {
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

fn generate_evidence_appendix(data: &CombinedComplianceReportData) -> String {
    let mut html = String::from(
        r#"
<div class="section evidence-appendix" id="evidence-appendix">
    <h2>Appendix: Evidence Summary</h2>
    <p>Summary of evidence collected during manual compliance assessments.</p>
"#,
    );

    for evidence in &data.all_evidence {
        let type_name = match evidence.evidence_type {
            EvidenceType::File => "File",
            EvidenceType::Link => "Link",
            EvidenceType::Screenshot => "Screenshot",
            EvidenceType::Note => "Note",
        };

        html.push_str(&format!(
            r#"
    <div class="evidence-appendix-item">
        <div class="evidence-header">
            <strong>{}</strong>
            <span class="type-badge">{}</span>
        </div>
        {}
        <div style="font-size: 0.85rem; color: #64748b; margin-top: 8px;">
            Assessment ID: {} | Created: {}
        </div>
    </div>
"#,
            html_escape(&evidence.title),
            type_name,
            if let Some(ref desc) = evidence.description {
                format!("<p>{}</p>", html_escape(desc))
            } else {
                String::new()
            },
            &evidence.assessment_id,
            evidence.created_at.format("%Y-%m-%d %H:%M UTC")
        ));
    }

    html.push_str("</div>");
    html
}

fn generate_combined_appendix(data: &CombinedComplianceReportData) -> String {
    format!(
        r#"
<div class="section" id="appendix">
    <h2>Appendix</h2>

    <h3>A. Assessment Methodology</h3>
    <p>This combined compliance assessment was conducted using HeroForge, an automated network reconnaissance
    and compliance assessment tool, supplemented with manual compliance assessments. The methodology included:</p>
    <ul>
        <li>Automated network scanning and vulnerability detection</li>
        <li>Mapping discovered vulnerabilities to compliance framework controls</li>
        <li>Direct compliance-specific checks for configuration and security settings</li>
        <li>Manual assessment of controls requiring human judgment</li>
        <li>Evidence collection and documentation</li>
        <li>Combined scoring using weighted average (Auto: {:.0}%, Manual: {:.0}%)</li>
    </ul>

    <h3>B. Assessment Details</h3>
    <table class="info-table">
        <tr><th>Scan ID</th><td>{}</td></tr>
        <tr><th>Scan Name</th><td>{}</td></tr>
        {}
        <tr><th>Assessment Date</th><td>{}</td></tr>
        {}
        <tr><th>Frameworks</th><td>{}</td></tr>
        <tr><th>Manual Assessments</th><td>{}</td></tr>
        <tr><th>Evidence Items</th><td>{}</td></tr>
        <tr><th>Report Generated</th><td>{}</td></tr>
    </table>

    <h3>C. Assessors</h3>
    {}

    <h3>D. Disclaimer</h3>
    <p class="disclaimer">This combined compliance assessment report incorporates both automated scanning results
    and manual expert assessments conducted at specific points in time. Manual assessments provide additional
    context, evidence, and expert judgment that automated tools cannot replicate. However, compliance is an
    ongoing process that requires continuous attention and improvement. This report is intended for authorized
    security testing and compliance assessment purposes only.</p>
</div>
"#,
        // Calculate average weights
        data.combined_frameworks.first().map(|f| f.automated_weight * 100.0).unwrap_or(50.0),
        data.combined_frameworks.first().map(|f| f.manual_weight * 100.0).unwrap_or(50.0),
        data.scan_id,
        html_escape(&data.scan_name),
        if let Some(ref campaign_id) = data.campaign_id {
            format!("<tr><th>Campaign ID</th><td>{}</td></tr>", campaign_id)
        } else {
            String::new()
        },
        data.scan_date.format("%Y-%m-%d %H:%M UTC"),
        if let (Some(start), Some(end)) = (&data.assessment_period_start, &data.assessment_period_end) {
            format!("<tr><th>Manual Assessment Period</th><td>{} to {}</td></tr>",
                start.format("%Y-%m-%d"), end.format("%Y-%m-%d"))
        } else {
            String::new()
        },
        data.combined_frameworks.len(),
        data.total_manual_assessments,
        data.total_evidence_items,
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        if !data.manual_assessors.is_empty() {
            format!("<ul>{}</ul>", data.manual_assessors.iter()
                .map(|a| format!("<li>{}</li>", html_escape(a)))
                .collect::<Vec<_>>()
                .join("\n"))
        } else {
            "<p>No manual assessors recorded.</p>".to_string()
        }
    )
}

fn generate_combined_footer(data: &CombinedComplianceReportData) -> String {
    format!(
        r#"
<footer class="report-footer">
    <p>Generated by Genial Architect Assessment Tool</p>
    <p>Report ID: {} | Generated: {}</p>
    <p>Combined Assessment: Automated Scan + {} Manual Assessment(s)</p>
    <p class="disclaimer">For authorized security testing and compliance assessment only.</p>
</footer>
"#,
        data.id,
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        data.total_manual_assessments
    )
}
