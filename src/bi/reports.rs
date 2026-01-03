//! Report templates and scheduling

use anyhow::Result;
use chrono::{DateTime, Utc};
use cron::Schedule;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::export::DataExporter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub id: String,
    pub name: String,
    pub template_type: ReportType,
    pub schedule: Option<String>, // Cron expression
    pub data_sources: Vec<DataSource>,
    pub format: OutputFormat,
    pub recipients: Vec<String>,
    pub filters: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReportType {
    ExecutiveSummary,
    VulnerabilityReport,
    ComplianceStatus,
    TrendAnalysis,
    AssetInventory,
    IncidentSummary,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSource {
    Scans,
    Vulnerabilities,
    Assets,
    Incidents,
    Compliance,
    Metrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Pdf,
    Excel,
    Csv,
    Html,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    pub template_id: String,
    pub next_run: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Scheduled,
    Running,
    Completed,
    Failed,
    Paused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedReport {
    pub id: String,
    pub template_id: String,
    pub generated_at: DateTime<Utc>,
    pub format: OutputFormat,
    pub size_bytes: usize,
    pub data: Vec<u8>,
}

pub struct ReportScheduler {
    templates: Arc<RwLock<HashMap<String, ReportTemplate>>>,
    scheduled_jobs: Arc<RwLock<HashMap<String, ScheduledJob>>>,
    exporter: DataExporter,
}

impl ReportScheduler {
    pub fn new() -> Self {
        Self {
            templates: Arc::new(RwLock::new(HashMap::new())),
            scheduled_jobs: Arc::new(RwLock::new(HashMap::new())),
            exporter: DataExporter::new(),
        }
    }

    /// Register a report template
    pub async fn register_template(&self, template: ReportTemplate) -> Result<String> {
        let template_id = template.id.clone();
        self.templates.write().await.insert(template_id.clone(), template);
        Ok(template_id)
    }

    /// Get a template by ID
    pub async fn get_template(&self, template_id: &str) -> Option<ReportTemplate> {
        self.templates.read().await.get(template_id).cloned()
    }

    /// List all templates
    pub async fn list_templates(&self) -> Vec<ReportTemplate> {
        self.templates.read().await.values().cloned().collect()
    }

    /// Schedule a report based on its cron expression
    pub async fn schedule_report(&self, template: &ReportTemplate) -> Result<String> {
        let cron_expr = template.schedule.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Template has no schedule defined"))?;

        // Parse and validate the cron expression
        let schedule = Schedule::from_str(cron_expr)
            .map_err(|e| anyhow::anyhow!("Invalid cron expression '{}': {}", cron_expr, e))?;

        // Calculate next run time
        let next_run = schedule.upcoming(Utc)
            .next()
            .ok_or_else(|| anyhow::anyhow!("Could not calculate next run time"))?;

        let job_id = Uuid::new_v4().to_string();
        let job = ScheduledJob {
            id: job_id.clone(),
            template_id: template.id.clone(),
            next_run,
            last_run: None,
            status: JobStatus::Scheduled,
        };

        self.scheduled_jobs.write().await.insert(job_id.clone(), job);

        Ok(job_id)
    }

    /// Get scheduled jobs
    pub async fn get_scheduled_jobs(&self) -> Vec<ScheduledJob> {
        self.scheduled_jobs.read().await.values().cloned().collect()
    }

    /// Get jobs due for execution
    pub async fn get_due_jobs(&self) -> Vec<ScheduledJob> {
        let now = Utc::now();
        self.scheduled_jobs.read().await
            .values()
            .filter(|job| job.status == JobStatus::Scheduled && job.next_run <= now)
            .cloned()
            .collect()
    }

    /// Pause a scheduled job
    pub async fn pause_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self.scheduled_jobs.write().await;
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| anyhow::anyhow!("Job not found: {}", job_id))?;
        job.status = JobStatus::Paused;
        Ok(())
    }

    /// Resume a paused job
    pub async fn resume_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self.scheduled_jobs.write().await;
        let job = jobs.get_mut(job_id)
            .ok_or_else(|| anyhow::anyhow!("Job not found: {}", job_id))?;
        if job.status == JobStatus::Paused {
            job.status = JobStatus::Scheduled;
        }
        Ok(())
    }

    /// Cancel a scheduled job
    pub async fn cancel_job(&self, job_id: &str) -> Result<()> {
        self.scheduled_jobs.write().await.remove(job_id);
        Ok(())
    }

    /// Generate a report from a template
    pub async fn generate_report(&self, template_id: &str) -> Result<Vec<u8>> {
        let template = self.get_template(template_id).await
            .ok_or_else(|| anyhow::anyhow!("Template not found: {}", template_id))?;

        // Collect data based on data sources
        let report_data = self.collect_report_data(&template).await?;

        // Generate report in requested format
        let report_bytes = match template.format {
            OutputFormat::Pdf => self.exporter.export_to_pdf(&report_data).await?,
            OutputFormat::Excel => self.exporter.export_to_excel(&report_data).await?,
            OutputFormat::Csv => self.exporter.export_to_csv(&report_data).await?.into_bytes(),
            OutputFormat::Html => self.generate_html_report(&template, &report_data).await?.into_bytes(),
            OutputFormat::Json => serde_json::to_string_pretty(&report_data)?.into_bytes(),
        };

        Ok(report_bytes)
    }

    /// Generate a report with custom data
    pub async fn generate_report_with_data(
        &self,
        template_id: &str,
        data: serde_json::Value,
    ) -> Result<GeneratedReport> {
        let template = self.get_template(template_id).await
            .ok_or_else(|| anyhow::anyhow!("Template not found: {}", template_id))?;

        let report_bytes = match template.format {
            OutputFormat::Pdf => self.exporter.export_to_pdf(&data).await?,
            OutputFormat::Excel => self.exporter.export_to_excel(&data).await?,
            OutputFormat::Csv => self.exporter.export_to_csv(&data).await?.into_bytes(),
            OutputFormat::Html => self.generate_html_report(&template, &data).await?.into_bytes(),
            OutputFormat::Json => serde_json::to_string_pretty(&data)?.into_bytes(),
        };

        Ok(GeneratedReport {
            id: Uuid::new_v4().to_string(),
            template_id: template_id.to_string(),
            generated_at: Utc::now(),
            format: template.format,
            size_bytes: report_bytes.len(),
            data: report_bytes,
        })
    }

    /// Collect report data based on template data sources
    async fn collect_report_data(&self, template: &ReportTemplate) -> Result<serde_json::Value> {
        let mut data = serde_json::Map::new();

        // Add report metadata
        data.insert("report_name".to_string(), serde_json::json!(template.name));
        data.insert("report_type".to_string(), serde_json::json!(format!("{:?}", template.template_type)));
        data.insert("generated_at".to_string(), serde_json::json!(Utc::now().to_rfc3339()));

        // Collect data from each source
        for source in &template.data_sources {
            let source_data = match source {
                DataSource::Scans => self.collect_scan_data(template).await?,
                DataSource::Vulnerabilities => self.collect_vulnerability_data(template).await?,
                DataSource::Assets => self.collect_asset_data(template).await?,
                DataSource::Incidents => self.collect_incident_data(template).await?,
                DataSource::Compliance => self.collect_compliance_data(template).await?,
                DataSource::Metrics => self.collect_metrics_data(template).await?,
            };
            data.insert(format!("{:?}", source).to_lowercase(), source_data);
        }

        // Apply filters if specified
        if let Some(ref filters) = template.filters {
            data.insert("applied_filters".to_string(), filters.clone());
        }

        Ok(serde_json::Value::Object(data))
    }

    async fn collect_scan_data(&self, template: &ReportTemplate) -> Result<serde_json::Value> {
        // Placeholder data structure - in production would query database
        let scan_summary = serde_json::json!({
            "total_scans": 0,
            "completed_scans": 0,
            "failed_scans": 0,
            "in_progress": 0,
            "last_scan": null,
            "scan_period": template.filters.as_ref()
                .and_then(|f| f.get("period"))
                .cloned()
                .unwrap_or(serde_json::json!("last_30_days"))
        });
        Ok(scan_summary)
    }

    async fn collect_vulnerability_data(&self, _template: &ReportTemplate) -> Result<serde_json::Value> {
        let vuln_summary = serde_json::json!({
            "total_vulnerabilities": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "remediated": 0,
            "pending": 0,
            "false_positives": 0
        });
        Ok(vuln_summary)
    }

    async fn collect_asset_data(&self, _template: &ReportTemplate) -> Result<serde_json::Value> {
        let asset_summary = serde_json::json!({
            "total_assets": 0,
            "by_type": {},
            "by_criticality": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "recently_discovered": 0,
            "offline": 0
        });
        Ok(asset_summary)
    }

    async fn collect_incident_data(&self, _template: &ReportTemplate) -> Result<serde_json::Value> {
        let incident_summary = serde_json::json!({
            "total_incidents": 0,
            "open": 0,
            "in_progress": 0,
            "resolved": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "mean_time_to_resolve": null
        });
        Ok(incident_summary)
    }

    async fn collect_compliance_data(&self, _template: &ReportTemplate) -> Result<serde_json::Value> {
        let compliance_summary = serde_json::json!({
            "overall_score": 0.0,
            "frameworks": [],
            "controls_passed": 0,
            "controls_failed": 0,
            "controls_not_applicable": 0,
            "last_assessment": null
        });
        Ok(compliance_summary)
    }

    async fn collect_metrics_data(&self, _template: &ReportTemplate) -> Result<serde_json::Value> {
        let metrics_summary = serde_json::json!({
            "mttd": null,
            "mttr": null,
            "mttc": null,
            "vulnerability_dwell_time": null,
            "patch_compliance_rate": null,
            "security_score": null
        });
        Ok(metrics_summary)
    }

    /// Generate HTML report from template
    async fn generate_html_report(
        &self,
        template: &ReportTemplate,
        data: &serde_json::Value,
    ) -> Result<String> {
        let mut html = String::from(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>"#);
        html.push_str(&escape_html(&template.name));
        html.push_str(r#"</title>
<style>
body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
h2 { color: #34495e; margin-top: 30px; }
.meta { color: #7f8c8d; font-size: 14px; margin-bottom: 30px; }
.section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
th { background-color: #3498db; color: white; }
tr:nth-child(even) { background-color: #f2f2f2; }
.stat-box { display: inline-block; background: #ecf0f1; padding: 15px 25px; margin: 10px; border-radius: 5px; text-align: center; }
.stat-value { font-size: 24px; font-weight: bold; color: #2980b9; }
.stat-label { font-size: 12px; color: #7f8c8d; }
.critical { color: #e74c3c; }
.high { color: #e67e22; }
.medium { color: #f39c12; }
.low { color: #27ae60; }
</style>
</head>
<body>
"#);

        // Header
        html.push_str(&format!("<h1>{}</h1>\n", escape_html(&template.name)));
        html.push_str(&format!(
            "<div class=\"meta\">Generated: {} | Type: {:?}</div>\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            template.template_type
        ));

        // Render data based on report type
        match template.template_type {
            ReportType::ExecutiveSummary => {
                html.push_str(&self.render_executive_summary(data));
            }
            ReportType::VulnerabilityReport => {
                html.push_str(&self.render_vulnerability_section(data));
            }
            ReportType::ComplianceStatus => {
                html.push_str(&self.render_compliance_section(data));
            }
            ReportType::TrendAnalysis => {
                html.push_str(&self.render_trend_section(data));
            }
            ReportType::AssetInventory => {
                html.push_str(&self.render_asset_section(data));
            }
            ReportType::IncidentSummary => {
                html.push_str(&self.render_incident_section(data));
            }
            ReportType::Custom => {
                html.push_str(&self.render_custom_section(data));
            }
        }

        html.push_str("</body></html>");
        Ok(html)
    }

    fn render_executive_summary(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Executive Summary</h2>\n");

        // Overview stats
        section.push_str("<div class=\"stats\">\n");
        if let Some(vulns) = data.get("vulnerabilities") {
            if let Some(total) = vulns.get("total_vulnerabilities") {
                section.push_str(&format!(
                    "<div class=\"stat-box\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Total Vulnerabilities</div></div>\n",
                    total
                ));
            }
        }
        if let Some(scans) = data.get("scans") {
            if let Some(total) = scans.get("total_scans") {
                section.push_str(&format!(
                    "<div class=\"stat-box\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Scans Completed</div></div>\n",
                    total
                ));
            }
        }
        if let Some(compliance) = data.get("compliance") {
            if let Some(score) = compliance.get("overall_score") {
                section.push_str(&format!(
                    "<div class=\"stat-box\"><div class=\"stat-value\">{}%</div><div class=\"stat-label\">Compliance Score</div></div>\n",
                    score
                ));
            }
        }
        section.push_str("</div>\n</div>\n");
        section
    }

    fn render_vulnerability_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Vulnerability Analysis</h2>\n");

        if let Some(vulns) = data.get("vulnerabilities") {
            if let Some(by_severity) = vulns.get("by_severity") {
                section.push_str("<table>\n<tr><th>Severity</th><th>Count</th></tr>\n");
                for (severity, count) in by_severity.as_object().unwrap_or(&serde_json::Map::new()) {
                    section.push_str(&format!(
                        "<tr><td class=\"{}\">{}</td><td>{}</td></tr>\n",
                        severity, severity.to_uppercase(), count
                    ));
                }
                section.push_str("</table>\n");
            }
        }

        section.push_str("</div>\n");
        section
    }

    fn render_compliance_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Compliance Status</h2>\n");

        if let Some(compliance) = data.get("compliance") {
            section.push_str("<table>\n<tr><th>Metric</th><th>Value</th></tr>\n");
            if let Some(score) = compliance.get("overall_score") {
                section.push_str(&format!(
                    "<tr><td>Overall Compliance Score</td><td>{}%</td></tr>\n",
                    score
                ));
            }
            if let Some(passed) = compliance.get("controls_passed") {
                section.push_str(&format!(
                    "<tr><td>Controls Passed</td><td>{}</td></tr>\n",
                    passed
                ));
            }
            if let Some(failed) = compliance.get("controls_failed") {
                section.push_str(&format!(
                    "<tr><td>Controls Failed</td><td>{}</td></tr>\n",
                    failed
                ));
            }
            section.push_str("</table>\n");
        }

        section.push_str("</div>\n");
        section
    }

    fn render_trend_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Trend Analysis</h2>\n");

        if let Some(metrics) = data.get("metrics") {
            section.push_str("<table>\n<tr><th>Metric</th><th>Value</th></tr>\n");
            if let Some(mttd) = metrics.get("mttd") {
                if !mttd.is_null() {
                    section.push_str(&format!(
                        "<tr><td>Mean Time to Detect (hours)</td><td>{:.2}</td></tr>\n",
                        mttd.as_f64().unwrap_or(0.0)
                    ));
                }
            }
            if let Some(mttr) = metrics.get("mttr") {
                if !mttr.is_null() {
                    section.push_str(&format!(
                        "<tr><td>Mean Time to Respond (hours)</td><td>{:.2}</td></tr>\n",
                        mttr.as_f64().unwrap_or(0.0)
                    ));
                }
            }
            section.push_str("</table>\n");
        }

        section.push_str("</div>\n");
        section
    }

    fn render_asset_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Asset Inventory</h2>\n");

        if let Some(assets) = data.get("assets") {
            section.push_str("<table>\n<tr><th>Metric</th><th>Count</th></tr>\n");
            if let Some(total) = assets.get("total_assets") {
                section.push_str(&format!(
                    "<tr><td>Total Assets</td><td>{}</td></tr>\n",
                    total
                ));
            }
            if let Some(discovered) = assets.get("recently_discovered") {
                section.push_str(&format!(
                    "<tr><td>Recently Discovered</td><td>{}</td></tr>\n",
                    discovered
                ));
            }
            if let Some(offline) = assets.get("offline") {
                section.push_str(&format!(
                    "<tr><td>Offline</td><td>{}</td></tr>\n",
                    offline
                ));
            }
            section.push_str("</table>\n");
        }

        section.push_str("</div>\n");
        section
    }

    fn render_incident_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Incident Summary</h2>\n");

        if let Some(incidents) = data.get("incidents") {
            section.push_str("<table>\n<tr><th>Status</th><th>Count</th></tr>\n");
            if let Some(open) = incidents.get("open") {
                section.push_str(&format!("<tr><td>Open</td><td>{}</td></tr>\n", open));
            }
            if let Some(in_progress) = incidents.get("in_progress") {
                section.push_str(&format!("<tr><td>In Progress</td><td>{}</td></tr>\n", in_progress));
            }
            if let Some(resolved) = incidents.get("resolved") {
                section.push_str(&format!("<tr><td>Resolved</td><td>{}</td></tr>\n", resolved));
            }
            section.push_str("</table>\n");
        }

        section.push_str("</div>\n");
        section
    }

    fn render_custom_section(&self, data: &serde_json::Value) -> String {
        let mut section = String::from("<div class=\"section\">\n<h2>Report Data</h2>\n<pre>");
        section.push_str(&escape_html(&serde_json::to_string_pretty(data).unwrap_or_default()));
        section.push_str("</pre>\n</div>\n");
        section
    }
}

impl Default for ReportScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Escape HTML special characters
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
