pub mod types;
pub mod formats;
pub mod risk_scoring;
pub mod remediation;
pub mod storage;

use anyhow::Result;
use log::info;
use sqlx::SqlitePool;

use crate::db;
use crate::types::HostInfo;
use types::{
    FindingDetail, RemediationRecommendation, ReportData, ReportFormat, ReportOptions,
    ReportSection, ReportSummary, ReportTemplate,
};

/// Report generator service
pub struct ReportGenerator {
    pool: SqlitePool,
    reports_dir: String,
}

impl ReportGenerator {
    /// Create a new report generator
    pub fn new(pool: SqlitePool, reports_dir: String) -> Self {
        ReportGenerator { pool, reports_dir }
    }

    /// Generate a report from scan results
    pub async fn generate(
        &self,
        report_id: &str,
        scan_id: &str,
        name: &str,
        description: Option<&str>,
        format: ReportFormat,
        template_id: &str,
        sections: Vec<String>,
        options: ReportOptions,
    ) -> Result<String> {
        info!("Generating {} report '{}' for scan {}", format.extension(), name, scan_id);

        // Update status to generating
        db::update_report_status(&self.pool, report_id, "generating", None, None, None).await?;

        // Get scan data
        let scan = db::get_scan_by_id(&self.pool, scan_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Scan not found: {}", scan_id))?;

        // Parse hosts from scan results
        let hosts: Vec<HostInfo> = if let Some(ref results_json) = scan.results {
            serde_json::from_str(results_json)?
        } else {
            return Err(anyhow::anyhow!("Scan has no results"));
        };

        // Get template
        let template = ReportTemplate::by_id(template_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown template: {}", template_id))?;

        // Parse sections
        let report_sections: Vec<ReportSection> = sections
            .iter()
            .filter_map(|s| ReportSection::from_str(s))
            .collect();

        let sections_to_use = if report_sections.is_empty() {
            template.default_sections.clone()
        } else {
            report_sections
        };

        // Build report data
        let summary = ReportSummary::from_hosts(&hosts);
        let findings = FindingDetail::from_vulnerabilities(&hosts);
        let remediation = RemediationRecommendation::from_findings(&findings);

        let report_data = ReportData {
            id: report_id.to_string(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            scan_id: scan_id.to_string(),
            scan_name: scan.name.clone(),
            created_at: chrono::Utc::now(),
            scan_date: scan.completed_at.unwrap_or(scan.created_at),
            template,
            sections: sections_to_use,
            options,
            hosts,
            summary,
            findings,
            remediation,
        };

        // Generate the report in the requested format
        let (file_path, file_size) = match format {
            ReportFormat::Json => {
                formats::json::generate(&report_data, &self.reports_dir).await?
            }
            ReportFormat::Html => {
                formats::html::generate(&report_data, &self.reports_dir).await?
            }
            ReportFormat::Pdf => {
                formats::pdf::generate(&report_data, &self.reports_dir).await?
            }
        };

        // Update status to completed
        db::update_report_status(
            &self.pool,
            report_id,
            "completed",
            Some(&file_path),
            Some(file_size),
            None,
        )
        .await?;

        info!("Report generated successfully: {}", file_path);
        Ok(file_path)
    }

    /// Get available templates
    pub fn get_templates() -> Vec<ReportTemplate> {
        ReportTemplate::all_templates()
    }
}
