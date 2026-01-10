pub mod types;
pub mod formats;
pub mod risk_scoring;
pub mod remediation;
pub mod storage;
pub mod compliance_report;
pub mod compliance;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{info, warn};
use sqlx::SqlitePool;
use std::path::PathBuf;

use crate::db;
use crate::screenshots::{ScreenshotOptions, ScreenshotService};
use crate::types::HostInfo;
use types::{
    FindingDetail, RemediationRecommendation, ReportData, ReportFormat, ReportOptions,
    ReportScreenshot, ReportSection, ReportSummary, ReportTemplate,
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

        // Fetch secret findings for this scan
        let secrets = db::secret_findings::get_findings_by_scan(&self.pool, scan_id)
            .await
            .unwrap_or_default();

        // Capture screenshots if enabled and Screenshots section is included
        let screenshots = if options.include_screenshots
            && sections_to_use.contains(&ReportSection::Screenshots)
        {
            self.capture_screenshots_for_hosts(&hosts, report_id).await
        } else {
            Vec::new()
        };

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
            secrets,
            remediation,
            screenshots,
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

    /// Capture screenshots for web services found in hosts
    async fn capture_screenshots_for_hosts(
        &self,
        hosts: &[HostInfo],
        report_id: &str,
    ) -> Vec<ReportScreenshot> {
        let mut screenshots = Vec::new();

        // Try to initialize screenshot service
        let service = match ScreenshotService::new() {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to initialize screenshot service: {}. Skipping screenshots.", e);
                return screenshots;
            }
        };

        // Create screenshots directory for this report
        let screenshots_dir = PathBuf::from(&self.reports_dir).join("screenshots").join(report_id);
        if let Err(e) = std::fs::create_dir_all(&screenshots_dir) {
            warn!("Failed to create screenshots directory: {}. Skipping screenshots.", e);
            return screenshots;
        }

        // Collect web services to screenshot
        let mut web_targets: Vec<(String, String, u16)> = Vec::new(); // (host_ip, url, port)

        for host in hosts {
            let host_ip = host.target.ip.to_string();

            for port in &host.ports {
                if port.state != crate::types::PortState::Open {
                    continue;
                }

                if let Some(ref service) = port.service {
                    let service_name = service.name.to_lowercase();

                    // Check if it's a web service
                    let is_http = service_name.contains("http")
                        || service_name.contains("web")
                        || port.port == 80
                        || port.port == 8080
                        || port.port == 8000
                        || port.port == 3000;

                    let is_https = service_name.contains("https")
                        || service_name.contains("ssl")
                        || service_name.contains("tls")
                        || port.port == 443
                        || port.port == 8443;

                    if is_http || is_https {
                        let protocol = if is_https { "https" } else { "http" };
                        let url = format!("{}://{}:{}", protocol, host_ip, port.port);
                        web_targets.push((host_ip.clone(), url, port.port));
                    }
                }
            }
        }

        // Capture screenshots for each web target
        for (i, (host_ip, url, port)) in web_targets.iter().enumerate() {
            info!("Capturing screenshot {} of {}: {}", i + 1, web_targets.len(), url);

            let filename = format!("{}_{}.png", host_ip.replace('.', "_"), port);
            let output_path = screenshots_dir.join(&filename);

            let options = ScreenshotOptions {
                url: url.clone(),
                output_path: output_path.clone(),
                full_page: false,
                timeout: 15000,
                wait: 2000,
                ignore_ssl: true, // Ignore SSL errors for security scanning
                ..Default::default()
            };

            match service.capture(&options).await {
                Ok(result) if result.success => {
                    // Read file and encode as base64 for embedding
                    let data_base64 = if let Some(ref path) = result.path {
                        match std::fs::read(path) {
                            Ok(data) => Some(BASE64.encode(&data)),
                            Err(e) => {
                                warn!("Failed to read screenshot file {}: {}", path, e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    let screenshot = ReportScreenshot {
                        id: uuid::Uuid::new_v4().to_string(),
                        url: url.clone(),
                        title: result.title.unwrap_or_else(|| format!("Screenshot of {}", url)),
                        description: Some(format!(
                            "Web service screenshot captured on port {}",
                            port
                        )),
                        file_path: output_path.to_string_lossy().to_string(),
                        width: result.width.unwrap_or(1920),
                        height: result.height.unwrap_or(1080),
                        captured_at: chrono::Utc::now(),
                        data_base64,
                        finding_id: None,
                        host_ip: Some(host_ip.clone()),
                    };

                    screenshots.push(screenshot);
                    info!("Screenshot captured successfully: {}", url);
                }
                Ok(result) => {
                    warn!(
                        "Screenshot capture failed for {}: {}",
                        url,
                        result.error.unwrap_or_else(|| "Unknown error".to_string())
                    );
                }
                Err(e) => {
                    warn!("Screenshot capture error for {}: {}", url, e);
                }
            }
        }

        info!("Captured {} screenshots for report", screenshots.len());
        screenshots
    }
}
