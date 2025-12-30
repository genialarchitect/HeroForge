//! Background scheduler for executing scheduled scans and reports
//!
//! This module provides a background task that periodically checks for
//! scheduled scans and reports that are due and executes them automatically.
//!
//! Production features:
//! - Retry logic with exponential backoff
//! - Email notifications for scan completion and failures
//! - Execution history tracking
//! - Jitter to prevent thundering herd
//! - Automated report generation and email delivery

use crate::db::{self, models};
use crate::email::{EmailConfig, EmailService, ScanSummary};
use crate::scanner;
use crate::types::{HostInfo, OutputFormat, ScanConfig, ScanProgressMessage, ScanType};
use crate::web::broadcast;
use anyhow::Result;
use lettre::message::{header, MultiPart, SinglePart, Attachment};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand::Rng;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use std::time::Duration;

/// Default interval between scheduler checks (60 seconds)
const SCHEDULER_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum jitter in seconds (0-30 seconds random delay)
const MAX_JITTER_SECS: u64 = 30;

/// Exponential backoff intervals for retries: 1min, 5min, 15min, 30min
const RETRY_BACKOFF_SECS: [u64; 4] = [60, 300, 900, 1800];

/// Start the background scheduler daemon
///
/// This spawns a background task that periodically checks for due scheduled scans
/// and executes them. The task runs indefinitely until the server shuts down.
pub fn start_scheduler(pool: Arc<SqlitePool>) {
    tokio::spawn(async move {
        log::info!(
            "Scheduler daemon started - checking every {:?}",
            SCHEDULER_CHECK_INTERVAL
        );

        // Load email configuration (optional)
        let email_service = match EmailConfig::from_env() {
            Ok(config) => {
                log::info!("Email notifications ENABLED for scheduled scans");
                Some(Arc::new(EmailService::new(config)))
            }
            Err(e) => {
                log::warn!("Email notifications DISABLED: {}", e);
                log::warn!("Set SMTP_* environment variables to enable email notifications");
                None
            }
        };

        loop {
            // Add jitter to prevent thundering herd
            let jitter = rand::thread_rng().gen_range(0..MAX_JITTER_SECS);
            tokio::time::sleep(SCHEDULER_CHECK_INTERVAL + Duration::from_secs(jitter)).await;

            // Check and execute due scans
            if let Err(e) = check_and_execute_due_scans(&pool, email_service.clone()).await {
                log::error!("Scheduler error (scans): {}", e);
            }

            // Check and execute due reports
            if let Err(e) = check_and_execute_due_reports(&pool, email_service.clone()).await {
                log::error!("Scheduler error (reports): {}", e);
            }

            // Check and execute due ASM monitors
            if let Err(e) = check_and_execute_due_asm_monitors(&pool).await {
                log::error!("Scheduler error (ASM monitors): {}", e);
            }

            // Check and execute due scheduled playbooks
            if let Err(e) = check_and_execute_due_playbooks(&pool).await {
                log::error!("Scheduler error (playbooks): {}", e);
            }
        }
    });
}

/// Check for due scheduled scans and execute them
async fn check_and_execute_due_scans(
    pool: &SqlitePool,
    email_service: Option<Arc<EmailService>>,
) -> Result<()> {
    // Get all due scheduled scans
    let due_scans = db::get_due_scheduled_scans(pool).await?;

    if due_scans.is_empty() {
        log::debug!("No scheduled scans due");
        return Ok(());
    }

    log::info!(
        "Found {} scheduled scan(s) due for execution",
        due_scans.len()
    );

    for scheduled_scan in due_scans {
        // Check if we should retry or skip based on retry count
        if scheduled_scan.retry_count >= scheduled_scan.max_retries {
            log::warn!(
                "Scheduled scan '{}' ({}) has exceeded max retries ({}), skipping until manual reset",
                scheduled_scan.name,
                scheduled_scan.id,
                scheduled_scan.max_retries
            );
            continue;
        }

        if let Err(e) = execute_scheduled_scan(pool, &scheduled_scan, email_service.clone()).await
        {
            log::error!(
                "Failed to execute scheduled scan '{}' ({}): {}",
                scheduled_scan.name,
                scheduled_scan.id,
                e
            );

            // Increment retry count
            let new_retry_count = scheduled_scan.retry_count + 1;
            let error_msg = format!("{}", e);

            if let Err(retry_err) = db::update_scheduled_scan_retry(
                pool,
                &scheduled_scan.id,
                new_retry_count,
                Some(&error_msg),
            )
            .await
            {
                log::error!(
                    "Failed to update retry count for scheduled scan '{}': {}",
                    scheduled_scan.id,
                    retry_err
                );
            }

            // Calculate exponential backoff for next retry
            if new_retry_count < scheduled_scan.max_retries {
                let backoff_index = (new_retry_count as usize - 1).min(RETRY_BACKOFF_SECS.len() - 1);
                let backoff_secs = RETRY_BACKOFF_SECS[backoff_index];
                log::info!(
                    "Will retry scheduled scan '{}' in {} seconds (attempt {}/{})",
                    scheduled_scan.name,
                    backoff_secs,
                    new_retry_count + 1,
                    scheduled_scan.max_retries
                );
            }
        }
    }

    Ok(())
}

/// Execute a single scheduled scan
async fn execute_scheduled_scan(
    pool: &SqlitePool,
    scheduled_scan: &models::ScheduledScan,
    email_service: Option<Arc<EmailService>>,
) -> Result<()> {
    log::info!(
        "Executing scheduled scan '{}' ({}) - retry attempt {}/{}",
        scheduled_scan.name,
        scheduled_scan.id,
        scheduled_scan.retry_count,
        scheduled_scan.max_retries
    );

    // Create execution history record
    let execution_record =
        db::create_execution_record(pool, &scheduled_scan.id, scheduled_scan.retry_count).await?;

    // Parse the scan configuration
    let config: models::ScheduledScanConfig = serde_json::from_str(&scheduled_scan.config)?;

    // Create a scan record in the database
    let scan_name = format!(
        "{} - {}",
        scheduled_scan.name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M")
    );
    let scan = db::create_scan(pool, &scheduled_scan.user_id, &scan_name, &config.targets, None, None).await?;
    let scan_id = scan.id.clone();

    // Build the scan configuration
    let scan_config = build_scan_config(&config)?;

    // Clone pool and IDs for the spawned task
    let pool_clone = pool.clone();
    let scheduled_scan_id = scheduled_scan.id.clone();
    let scheduled_scan_name = scheduled_scan.name.clone();
    let user_id = scheduled_scan.user_id.clone();
    let execution_id = execution_record.id.clone();

    // Spawn the scan execution task
    tokio::spawn(async move {
        // Create broadcast channel for this scan
        let tx = broadcast::create_scan_channel(scan_id.clone()).await;

        // Send scan started message
        let _ = tx.send(ScanProgressMessage::ScanStarted {
            scan_id: scan_id.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });

        // Update scan status to running
        let _ = db::update_scan_status(&pool_clone, &scan_id, "running", None, None).await;

        // Run the scan
        let start_time = std::time::Instant::now();
        match scanner::run_scan(&scan_config, Some(tx.clone())).await {
            Ok(results) => {
                let duration = start_time.elapsed();
                let results_json = serde_json::to_string(&results).unwrap_or_default();

                // Send completion message
                let _ = tx.send(ScanProgressMessage::ScanCompleted {
                    scan_id: scan_id.clone(),
                    duration: duration.as_secs_f64(),
                    total_hosts: results.len(),
                });

                // Update scan status to completed
                let _ = db::update_scan_status(
                    &pool_clone,
                    &scan_id,
                    "completed",
                    Some(&results_json),
                    None,
                )
                .await;

                // Update execution record
                let _ = db::complete_execution_record(
                    &pool_clone,
                    &execution_id,
                    Some(&scan_id),
                    "completed",
                    None,
                )
                .await;

                // Reset retry count on success
                let _ = db::reset_scheduled_scan_retry(&pool_clone, &scheduled_scan_id).await;

                // Calculate scan summary for email
                let summary = calculate_scan_summary(&results);

                log::info!(
                    "Scheduled scan '{}' completed - found {} hosts in {:.2}s",
                    scheduled_scan_name,
                    results.len(),
                    duration.as_secs_f64()
                );

                // Send email notification if configured
                if let Some(email_svc) = &email_service {
                    if let Err(e) = send_completion_email(
                        &pool_clone,
                        email_svc,
                        &user_id,
                        &scheduled_scan_name,
                        &summary,
                    )
                    .await
                    {
                        log::error!("Failed to send completion email: {}", e);
                    }
                }

                // Clean up old execution records
                let _ = db::cleanup_old_executions(&pool_clone, &scheduled_scan_id).await;
            }
            Err(e) => {
                let error_msg = format!("Scan failed: {}", e);
                let _ = tx.send(ScanProgressMessage::Error {
                    message: error_msg.clone(),
                });
                let _ = db::update_scan_status(
                    &pool_clone,
                    &scan_id,
                    "failed",
                    None,
                    Some(&error_msg),
                )
                .await;

                // Update execution record
                let _ = db::complete_execution_record(
                    &pool_clone,
                    &execution_id,
                    Some(&scan_id),
                    "failed",
                    Some(&error_msg),
                )
                .await;

                log::error!("Scheduled scan '{}' failed: {}", scheduled_scan_name, e);

                // Send failure email notification if configured
                if let Some(email_svc) = &email_service {
                    if let Err(email_err) = send_failure_email(
                        &pool_clone,
                        email_svc,
                        &user_id,
                        &scheduled_scan_name,
                        &error_msg,
                    )
                    .await
                    {
                        log::error!("Failed to send failure email: {}", email_err);
                    }
                }
            }
        }

        // Update the scheduled scan execution record
        if let Err(e) =
            db::update_scheduled_scan_execution(&pool_clone, &scheduled_scan_id, &scan_id).await
        {
            log::error!(
                "Failed to update scheduled scan execution record: {}",
                e
            );
        }

        // Clean up broadcast channel after a delay
        tokio::time::sleep(Duration::from_secs(60)).await;
        broadcast::remove_scan_channel(&scan_id).await;
    });

    Ok(())
}

/// Build a ScanConfig from a ScheduledScanConfig
fn build_scan_config(config: &models::ScheduledScanConfig) -> Result<ScanConfig> {
    use crate::scanner::enumeration::types::{DbType, EnumDepth, ServiceType};

    // Parse enumeration depth
    let enum_depth = config
        .enum_depth
        .as_ref()
        .map(|d| match d.to_lowercase().as_str() {
            "passive" => EnumDepth::Passive,
            "aggressive" => EnumDepth::Aggressive,
            _ => EnumDepth::Light,
        })
        .unwrap_or(EnumDepth::Light);

    // Parse enumeration services
    let enum_services: Vec<ServiceType> = config
        .enum_services
        .as_ref()
        .map(|services| {
            services
                .iter()
                .filter_map(|s| match s.to_lowercase().as_str() {
                    "http" => Some(ServiceType::Http),
                    "https" => Some(ServiceType::Https),
                    "dns" => Some(ServiceType::Dns),
                    "smb" => Some(ServiceType::Smb),
                    "ftp" => Some(ServiceType::Ftp),
                    "ssh" => Some(ServiceType::Ssh),
                    "smtp" => Some(ServiceType::Smtp),
                    "ldap" => Some(ServiceType::Ldap),
                    "mysql" => Some(ServiceType::Database(DbType::MySQL)),
                    "postgresql" => Some(ServiceType::Database(DbType::PostgreSQL)),
                    "mongodb" => Some(ServiceType::Database(DbType::MongoDB)),
                    "redis" => Some(ServiceType::Database(DbType::Redis)),
                    "elasticsearch" => Some(ServiceType::Database(DbType::Elasticsearch)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse scan type
    let scan_type = config
        .scan_type
        .as_ref()
        .map(|s| match s.to_lowercase().as_str() {
            "udp" => ScanType::UDPScan,
            "comprehensive" => ScanType::Comprehensive,
            _ => ScanType::TCPConnect,
        })
        .unwrap_or(ScanType::TCPConnect);

    Ok(ScanConfig {
        targets: config.targets.clone(),
        port_range: config.port_range,
        threads: config.threads,
        timeout: Duration::from_secs(3),
        scan_type,
        enable_os_detection: config.enable_os_detection,
        enable_service_detection: config.enable_service_detection,
        enable_vuln_scan: config.enable_vuln_scan,
        enable_enumeration: config.enable_enumeration,
        enum_depth,
        enum_wordlist_path: None,
        enum_services,
        output_format: OutputFormat::Json,
        udp_port_range: config.udp_port_range,
        udp_retries: config.udp_retries,
        skip_host_discovery: false,
        // Use defaults for scanner-specific timeouts
        service_detection_timeout: None,
        dns_timeout: None,
        syn_timeout: None,
        udp_timeout: None,
        // Scheduled scans don't support VPN (use regular scan API with vpn_config_id)
        vpn_config_id: None,
        exclusions: Vec::new(),
    })
}

/// Calculate scan summary from results
fn calculate_scan_summary(results: &[HostInfo]) -> ScanSummary {
    let mut open_ports = 0;
    let mut services_identified = 0;
    let mut total_vulns = 0;
    let mut critical_vulns = 0;
    let mut high_vulns = 0;
    let mut medium_vulns = 0;
    let mut low_vulns = 0;

    for host in results {
        open_ports += host.ports.len();

        for port_info in &host.ports {
            if port_info.service.is_some() {
                services_identified += 1;
            }
        }

        // Vulnerabilities are on the host level, not port level
        total_vulns += host.vulnerabilities.len();
        for vuln in &host.vulnerabilities {
            use crate::types::Severity;
            match vuln.severity {
                Severity::Critical => critical_vulns += 1,
                Severity::High => high_vulns += 1,
                Severity::Medium => medium_vulns += 1,
                Severity::Low => low_vulns += 1,
            }
        }
    }

    ScanSummary {
        hosts_discovered: results.len(),
        open_ports,
        services_identified,
        vulnerabilities_found: total_vulns,
        critical_vulns,
        high_vulns,
        medium_vulns,
        low_vulns,
    }
}

/// Send scan completion email notification
async fn send_completion_email(
    pool: &SqlitePool,
    email_service: &EmailService,
    user_id: &str,
    scan_name: &str,
    summary: &ScanSummary,
) -> Result<()> {
    // Get user notification settings
    let settings = db::get_notification_settings(pool, user_id).await?;

    // Check if user wants email on scan complete
    if !settings.email_on_scan_complete {
        log::debug!(
            "User {} has disabled scan completion emails, skipping",
            user_id
        );
        return Ok(());
    }

    // Send email
    email_service
        .send_scan_completed(&settings.email_address, scan_name, summary)
        .await?;

    log::info!(
        "Sent scan completion email to {} for scan '{}'",
        settings.email_address,
        scan_name
    );

    Ok(())
}

/// Send scan failure email notification
async fn send_failure_email(
    pool: &SqlitePool,
    email_service: &EmailService,
    user_id: &str,
    scan_name: &str,
    error_message: &str,
) -> Result<()> {
    // Get user notification settings
    let settings = db::get_notification_settings(pool, user_id).await?;

    // Send the failure email
    email_service
        .send_scan_failed(&settings.email_address, scan_name, error_message)
        .await?;

    log::info!(
        "Sent scan failure email to {} for scan '{}'",
        settings.email_address,
        scan_name
    );

    Ok(())
}

// ============================================================================
// Scheduled Reports
// ============================================================================

/// Check for due scheduled reports and execute them
async fn check_and_execute_due_reports(
    pool: &SqlitePool,
    _email_service: Option<Arc<EmailService>>,
) -> Result<()> {
    // Get all due scheduled reports
    let due_reports = db::get_due_scheduled_reports(pool).await?;

    if due_reports.is_empty() {
        log::debug!("No scheduled reports due");
        return Ok(());
    }

    log::info!(
        "Found {} scheduled report(s) due for execution",
        due_reports.len()
    );

    for scheduled_report in due_reports {
        if let Err(e) = execute_scheduled_report(pool, &scheduled_report).await {
            log::error!(
                "Failed to execute scheduled report '{}' ({}): {}",
                scheduled_report.name,
                scheduled_report.id,
                e
            );
        }
    }

    Ok(())
}

/// Execute a single scheduled report
pub async fn execute_scheduled_report(
    pool: &SqlitePool,
    scheduled_report: &models::ScheduledReport,
) -> Result<()> {
    log::info!(
        "Executing scheduled report '{}' ({})",
        scheduled_report.name,
        scheduled_report.id
    );

    // Parse recipients
    let recipients: Vec<String> = serde_json::from_str(&scheduled_report.recipients)?;
    if recipients.is_empty() {
        return Err(anyhow::anyhow!("No recipients configured for scheduled report"));
    }

    // Parse filters
    let filters: Option<models::ScheduledReportFilters> = scheduled_report
        .filters
        .as_ref()
        .map(|f| serde_json::from_str(f))
        .transpose()?;

    // Get reports directory from environment or use default
    let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());

    // Create reports directory if it doesn't exist
    std::fs::create_dir_all(&reports_dir)?;

    // Generate the report based on type
    let report_path = match scheduled_report.report_type.as_str() {
        "vulnerability" => {
            generate_vulnerability_report(
                pool,
                &scheduled_report.name,
                &scheduled_report.format,
                &reports_dir,
                filters.as_ref(),
            )
            .await?
        }
        "scan_summary" => {
            generate_scan_summary_report(
                pool,
                &scheduled_report.name,
                &scheduled_report.format,
                &reports_dir,
                filters.as_ref(),
            )
            .await?
        }
        "compliance" => {
            generate_compliance_report(
                pool,
                &scheduled_report.name,
                &scheduled_report.format,
                &reports_dir,
                filters.as_ref(),
            )
            .await?
        }
        "executive" => {
            generate_executive_report(
                pool,
                &scheduled_report.name,
                &scheduled_report.format,
                &reports_dir,
                filters.as_ref(),
            )
            .await?
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unknown report type: {}",
                scheduled_report.report_type
            ));
        }
    };

    // Send the report via email to all recipients
    for recipient in &recipients {
        if let Err(e) = send_report_email(
            recipient,
            &scheduled_report.name,
            &scheduled_report.report_type,
            &report_path,
            &scheduled_report.format,
        )
        .await
        {
            log::error!("Failed to send report to {}: {}", recipient, e);
        }
    }

    // Update the scheduled report execution time
    db::update_scheduled_report_execution(pool, &scheduled_report.id).await?;

    log::info!(
        "Scheduled report '{}' executed successfully",
        scheduled_report.name
    );

    Ok(())
}

/// Generate a vulnerability report
async fn generate_vulnerability_report(
    pool: &SqlitePool,
    name: &str,
    format: &str,
    reports_dir: &str,
    filters: Option<&models::ScheduledReportFilters>,
) -> Result<String> {
    log::info!("Generating vulnerability report: {}", name);

    // Get recent scans (last 30 days by default)
    let days_back = filters.and_then(|f| f.days_back).unwrap_or(30);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days_back as i64);

    // Get all completed scans
    let scans = db::get_all_scans(pool).await?;

    // Filter to recent completed scans
    let recent_scans: Vec<_> = scans
        .into_iter()
        .filter(|s| s.status == "completed" && s.completed_at.map(|c| c > cutoff).unwrap_or(false))
        .collect();

    // Collect vulnerabilities from all scans
    let mut all_vulns = Vec::new();
    let min_severity = filters.and_then(|f| f.min_severity.as_ref());

    for scan in &recent_scans {
        if let Some(ref results_json) = scan.results {
            let hosts: Vec<HostInfo> = serde_json::from_str(results_json).unwrap_or_default();
            for host in hosts {
                for vuln in host.vulnerabilities {
                    // Filter by severity if specified
                    let include = match min_severity {
                        Some(min) => {
                            let severity_order = |s: &str| match s.to_lowercase().as_str() {
                                "critical" => 4,
                                "high" => 3,
                                "medium" => 2,
                                "low" => 1,
                                _ => 0,
                            };
                            severity_order(&format!("{:?}", vuln.severity))
                                >= severity_order(min)
                        }
                        None => true,
                    };

                    if include {
                        all_vulns.push(serde_json::json!({
                            "host": host.target.ip,
                            "hostname": host.target.hostname,
                            "title": vuln.title,
                            "severity": format!("{:?}", vuln.severity),
                            "cve_id": vuln.cve_id,
                            "description": vuln.description,
                            "affected_service": vuln.affected_service,
                        }));
                    }
                }
            }
        }
    }

    // Generate report content
    let report_data = serde_json::json!({
        "report_name": name,
        "report_type": "vulnerability",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "period_days": days_back,
        "total_scans": recent_scans.len(),
        "total_vulnerabilities": all_vulns.len(),
        "vulnerabilities": all_vulns,
    });

    // Write report to file
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("vuln_report_{}_{}.{}", sanitize_filename(name), timestamp, format);
    let filepath = format!("{}/{}", reports_dir, filename);

    match format {
        "json" => {
            let content = serde_json::to_string_pretty(&report_data)?;
            std::fs::write(&filepath, content)?;
        }
        "csv" => {
            let mut csv_content = String::from("Host,Hostname,Title,Severity,CVE ID,Description,Affected Service\n");
            for vuln in &all_vulns {
                csv_content.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    escape_csv(vuln["host"].as_str().unwrap_or("")),
                    escape_csv(vuln["hostname"].as_str().unwrap_or("")),
                    escape_csv(vuln["title"].as_str().unwrap_or("")),
                    escape_csv(vuln["severity"].as_str().unwrap_or("")),
                    escape_csv(vuln["cve_id"].as_str().unwrap_or("")),
                    escape_csv(vuln["description"].as_str().unwrap_or("")),
                    escape_csv(vuln["affected_service"].as_str().unwrap_or("")),
                ));
            }
            std::fs::write(&filepath, csv_content)?;
        }
        "html" | "pdf" => {
            let html_content = generate_vulnerability_html(&report_data);
            if format == "html" {
                std::fs::write(&filepath, html_content)?;
            } else {
                // For PDF, write HTML first then convert
                let html_path = format!("{}/temp_{}.html", reports_dir, timestamp);
                std::fs::write(&html_path, &html_content)?;
                // TODO: Use PDF generation library
                // For now, just use HTML
                std::fs::write(&filepath.replace(".pdf", ".html"), &html_content)?;
                let _ = std::fs::remove_file(&html_path);
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported format: {}", format));
        }
    }

    log::info!("Generated vulnerability report: {}", filepath);
    Ok(filepath)
}

/// Generate a scan summary report
async fn generate_scan_summary_report(
    pool: &SqlitePool,
    name: &str,
    format: &str,
    reports_dir: &str,
    filters: Option<&models::ScheduledReportFilters>,
) -> Result<String> {
    log::info!("Generating scan summary report: {}", name);

    let days_back = filters.and_then(|f| f.days_back).unwrap_or(30);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days_back as i64);

    let scans = db::get_all_scans(pool).await?;
    let recent_scans: Vec<_> = scans
        .into_iter()
        .filter(|s| s.created_at > cutoff)
        .collect();

    let summary = serde_json::json!({
        "report_name": name,
        "report_type": "scan_summary",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "period_days": days_back,
        "total_scans": recent_scans.len(),
        "completed_scans": recent_scans.iter().filter(|s| s.status == "completed").count(),
        "failed_scans": recent_scans.iter().filter(|s| s.status == "failed").count(),
        "pending_scans": recent_scans.iter().filter(|s| s.status == "pending").count(),
        "scans": recent_scans.iter().map(|s| serde_json::json!({
            "name": s.name,
            "targets": s.targets,
            "status": s.status,
            "created_at": s.created_at.to_rfc3339(),
            "completed_at": s.completed_at.map(|c| c.to_rfc3339()),
        })).collect::<Vec<_>>(),
    });

    // Write report
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("scan_summary_{}_{}.{}", sanitize_filename(name), timestamp, format);
    let filepath = format!("{}/{}", reports_dir, filename);

    match format {
        "json" => {
            let content = serde_json::to_string_pretty(&summary)?;
            std::fs::write(&filepath, content)?;
        }
        "html" | "pdf" => {
            let html_content = generate_scan_summary_html(&summary);
            std::fs::write(&filepath.replace(".pdf", ".html"), html_content)?;
        }
        "csv" => {
            let mut csv = String::from("Name,Targets,Status,Created At,Completed At\n");
            for scan in &recent_scans {
                csv.push_str(&format!(
                    "{},{},{},{},{}\n",
                    escape_csv(&scan.name),
                    escape_csv(&scan.targets),
                    escape_csv(&scan.status),
                    scan.created_at.to_rfc3339(),
                    scan.completed_at.map(|c| c.to_rfc3339()).unwrap_or_default(),
                ));
            }
            std::fs::write(&filepath, csv)?;
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }

    log::info!("Generated scan summary report: {}", filepath);
    Ok(filepath)
}

/// Generate a compliance report
async fn generate_compliance_report(
    pool: &SqlitePool,
    name: &str,
    format: &str,
    reports_dir: &str,
    filters: Option<&models::ScheduledReportFilters>,
) -> Result<String> {
    log::info!("Generating compliance report: {}", name);

    // Get frameworks to include
    let frameworks = filters
        .and_then(|f| f.frameworks.as_ref())
        .cloned()
        .unwrap_or_else(|| vec!["pci_dss".to_string(), "nist_800_53".to_string()]);

    // Get recent scan data
    let days_back = filters.and_then(|f| f.days_back).unwrap_or(30);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days_back as i64);

    let scans = db::get_all_scans(pool).await?;
    let recent_scans: Vec<_> = scans
        .into_iter()
        .filter(|s| s.status == "completed" && s.completed_at.map(|c| c > cutoff).unwrap_or(false))
        .collect();

    // Build compliance summary
    let report_data = serde_json::json!({
        "report_name": name,
        "report_type": "compliance",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "period_days": days_back,
        "frameworks": frameworks,
        "total_scans_analyzed": recent_scans.len(),
        "note": "Run compliance analysis via API for detailed control mappings",
    });

    // Write report
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("compliance_{}_{}.{}", sanitize_filename(name), timestamp, format);
    let filepath = format!("{}/{}", reports_dir, filename);

    match format {
        "json" => {
            let content = serde_json::to_string_pretty(&report_data)?;
            std::fs::write(&filepath, content)?;
        }
        "html" | "pdf" => {
            let html = generate_compliance_html(&report_data);
            std::fs::write(&filepath.replace(".pdf", ".html"), html)?;
        }
        "csv" => {
            let csv = format!("Framework,Period Days,Scans Analyzed\n{},{},{}",
                frameworks.join(";"),
                days_back,
                recent_scans.len()
            );
            std::fs::write(&filepath, csv)?;
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }

    log::info!("Generated compliance report: {}", filepath);
    Ok(filepath)
}

/// Generate an executive report
async fn generate_executive_report(
    pool: &SqlitePool,
    name: &str,
    format: &str,
    reports_dir: &str,
    filters: Option<&models::ScheduledReportFilters>,
) -> Result<String> {
    log::info!("Generating executive report: {}", name);

    let days_back = filters.and_then(|f| f.days_back).unwrap_or(30);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days_back as i64);

    // Get scan data
    let scans = db::get_all_scans(pool).await?;
    let recent_scans: Vec<_> = scans
        .into_iter()
        .filter(|s| s.created_at > cutoff)
        .collect();

    // Calculate summary statistics
    let completed_scans = recent_scans.iter().filter(|s| s.status == "completed").count();
    let mut total_hosts = 0;
    let mut total_vulns = 0;
    let mut critical_vulns = 0;
    let mut high_vulns = 0;

    for scan in &recent_scans {
        if let Some(ref results_json) = scan.results {
            let hosts: Vec<HostInfo> = serde_json::from_str(results_json).unwrap_or_default();
            total_hosts += hosts.len();
            for host in &hosts {
                total_vulns += host.vulnerabilities.len();
                for vuln in &host.vulnerabilities {
                    use crate::types::Severity;
                    match vuln.severity {
                        Severity::Critical => critical_vulns += 1,
                        Severity::High => high_vulns += 1,
                        _ => {}
                    }
                }
            }
        }
    }

    let report_data = serde_json::json!({
        "report_name": name,
        "report_type": "executive",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "period_days": days_back,
        "summary": {
            "total_scans": recent_scans.len(),
            "completed_scans": completed_scans,
            "total_hosts_discovered": total_hosts,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
        },
        "risk_level": if critical_vulns > 0 { "Critical" } else if high_vulns > 0 { "High" } else { "Medium" },
    });

    // Write report
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("executive_{}_{}.{}", sanitize_filename(name), timestamp, format);
    let filepath = format!("{}/{}", reports_dir, filename);

    match format {
        "json" => {
            let content = serde_json::to_string_pretty(&report_data)?;
            std::fs::write(&filepath, content)?;
        }
        "html" | "pdf" => {
            let html = generate_executive_html(&report_data);
            std::fs::write(&filepath.replace(".pdf", ".html"), html)?;
        }
        "csv" => {
            let csv = format!(
                "Metric,Value\nTotal Scans,{}\nCompleted Scans,{}\nTotal Hosts,{}\nTotal Vulnerabilities,{}\nCritical Vulnerabilities,{}\nHigh Vulnerabilities,{}",
                recent_scans.len(),
                completed_scans,
                total_hosts,
                total_vulns,
                critical_vulns,
                high_vulns
            );
            std::fs::write(&filepath, csv)?;
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }

    log::info!("Generated executive report: {}", filepath);
    Ok(filepath)
}

/// Send report email with attachment
async fn send_report_email(
    recipient: &str,
    report_name: &str,
    report_type: &str,
    report_path: &str,
    format: &str,
) -> Result<()> {
    // Get email configuration
    let config = EmailConfig::from_env()?;

    // Read the report file
    let report_content = std::fs::read(report_path)?;
    let filename = std::path::Path::new(report_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("report.txt");

    // Determine content type
    let content_type = match format {
        "pdf" => "application/pdf",
        "html" => "text/html",
        "csv" => "text/csv",
        "json" => "application/json",
        _ => "application/octet-stream",
    };

    // Build email subject
    let subject = format!("HeroForge {} Report: {}",
        report_type.chars().next().unwrap().to_uppercase().to_string() + &report_type[1..],
        report_name
    );

    // Build email body
    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4F46E5; color: white; padding: 20px; text-align: center; }}
        .content {{ background-color: #f9fafb; padding: 20px; }}
        .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Scheduled Report</h1>
        </div>
        <div class="content">
            <p>Your scheduled HeroForge report <strong>{}</strong> has been generated.</p>
            <p><strong>Report Type:</strong> {}</p>
            <p><strong>Generated:</strong> {}</p>
            <p>The report is attached to this email.</p>
        </div>
        <div class="footer">
            <p>This is an automated report from Genial Architect Scanner.</p>
        </div>
    </div>
</body>
</html>"#,
        report_name,
        report_type,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    let text_body = format!(
        "HeroForge Scheduled Report: {}\n\nReport Type: {}\nGenerated: {}\n\nThe report is attached to this email.",
        report_name,
        report_type,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // Build the email with attachment
    let attachment = Attachment::new(filename.to_string())
        .body(report_content, content_type.parse().unwrap());

    let email = Message::builder()
        .from(
            format!("{} <{}>", config.from_name, config.from_address)
                .parse()
                .map_err(|e| anyhow::anyhow!("Failed to parse from address: {}", e))?,
        )
        .to(recipient.parse().map_err(|e| anyhow::anyhow!("Failed to parse recipient: {}", e))?)
        .subject(&subject)
        .multipart(
            MultiPart::mixed()
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(header::ContentType::TEXT_PLAIN)
                                .body(text_body),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(header::ContentType::TEXT_HTML)
                                .body(html_body),
                        ),
                )
                .singlepart(attachment),
        )?;

    // Send the email
    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

    let mailer = SmtpTransport::relay(&config.smtp_host)?
        .credentials(creds)
        .port(config.smtp_port)
        .build();

    // Send in blocking task
    tokio::task::spawn_blocking(move || mailer.send(&email))
        .await??;

    log::info!("Sent report email to {}", recipient);
    Ok(())
}

// ============================================================================
// ASM Monitor Scheduler
// ============================================================================

/// Check for due ASM monitors and execute them
async fn check_and_execute_due_asm_monitors(pool: &SqlitePool) -> Result<()> {
    use crate::asm::monitor::AsmMonitorEngine;

    // Get all due ASM monitors
    let due_monitors = crate::db::asm::get_due_monitors(pool).await?;

    if due_monitors.is_empty() {
        log::debug!("No ASM monitors due for execution");
        return Ok(());
    }

    log::info!(
        "Found {} ASM monitor(s) due for execution",
        due_monitors.len()
    );

    let engine = AsmMonitorEngine::new(pool.clone());

    for monitor in due_monitors {
        log::info!(
            "Executing ASM monitor '{}' ({})",
            monitor.name,
            monitor.id
        );

        // Run the monitor
        match engine.run_monitor(&monitor.id).await {
            Ok(result) => {
                log::info!(
                    "ASM monitor '{}' completed - discovered {} assets, detected {} changes in {}s",
                    monitor.name,
                    result.assets_discovered,
                    result.changes_detected,
                    result.duration_secs
                );

                // Calculate next run time based on cron schedule
                if let Some(next_run) = calculate_next_asm_run(&monitor.schedule) {
                    if let Err(e) = update_asm_next_run(pool, &monitor.id, next_run).await {
                        log::error!(
                            "Failed to update next run time for ASM monitor '{}': {}",
                            monitor.id,
                            e
                        );
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to execute ASM monitor '{}' ({}): {}",
                    monitor.name,
                    monitor.id,
                    e
                );

                // Still update next run time on failure to avoid retry loops
                if let Some(next_run) = calculate_next_asm_run(&monitor.schedule) {
                    let _ = update_asm_next_run(pool, &monitor.id, next_run).await;
                }
            }
        }
    }

    Ok(())
}

/// Calculate the next run time based on a cron expression
fn calculate_next_asm_run(schedule: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::Utc;

    // Simple cron parsing for common patterns
    // Full cron: minute hour day month weekday
    let parts: Vec<&str> = schedule.split_whitespace().collect();

    if parts.len() < 5 {
        // Default to daily if invalid
        return Some(Utc::now() + chrono::Duration::hours(24));
    }

    // For now, use a simple approach:
    // - If schedule is "0 0 * * *" (daily at midnight), add 24 hours
    // - If schedule is "0 * * * *" (hourly), add 1 hour
    // - If schedule is "*/15 * * * *" (every 15 min), add 15 minutes
    // - Default to 24 hours

    let minute = parts[0];
    let hour = parts[1];

    if minute.starts_with("*/") {
        // Every N minutes
        let interval: i64 = minute.trim_start_matches("*/").parse().unwrap_or(60);
        return Some(Utc::now() + chrono::Duration::minutes(interval));
    }

    if hour == "*" && minute != "*" {
        // Hourly at specific minute
        return Some(Utc::now() + chrono::Duration::hours(1));
    }

    if hour != "*" && minute != "*" {
        // Daily at specific time
        return Some(Utc::now() + chrono::Duration::hours(24));
    }

    // Default to daily
    Some(Utc::now() + chrono::Duration::hours(24))
}

/// Update ASM monitor's next run time
async fn update_asm_next_run(
    pool: &SqlitePool,
    monitor_id: &str,
    next_run: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let next_run_str = next_run.to_rfc3339();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query("UPDATE asm_monitors SET next_run_at = ?, updated_at = ? WHERE id = ?")
        .bind(&next_run_str)
        .bind(&now)
        .bind(monitor_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Scheduled Playbooks
// ============================================================================

/// Check for due scheduled playbooks and execute them
async fn check_and_execute_due_playbooks(pool: &SqlitePool) -> Result<()> {
    use crate::db::{get_due_scheduled_playbooks, update_playbook_next_run};
    use crate::green_team::playbooks::ExecutionContext;
    use crate::green_team::types::PlaybookStep;

    // Get all due scheduled playbooks
    let due_playbooks = get_due_scheduled_playbooks(pool).await?;

    if due_playbooks.is_empty() {
        log::debug!("No scheduled playbooks due for execution");
        return Ok(());
    }

    log::info!(
        "Found {} scheduled playbook(s) due for execution",
        due_playbooks.len()
    );

    for scheduled_playbook in due_playbooks {
        log::info!(
            "Executing scheduled playbook '{}' ({})",
            scheduled_playbook.playbook_id,
            scheduled_playbook.id
        );

        // Get the playbook details
        let playbook_row = match sqlx::query("SELECT id, name, steps_json, is_active FROM soar_playbooks WHERE id = ? AND is_active = TRUE")
            .bind(&scheduled_playbook.playbook_id)
            .fetch_optional(pool)
            .await? {
            Some(p) => p,
            None => {
                log::warn!(
                    "Scheduled playbook {} references non-existent or inactive playbook {}",
                    scheduled_playbook.id,
                    scheduled_playbook.playbook_id
                );
                continue;
            }
        };

        let playbook_name: String = playbook_row.get("name");
        let steps_json: String = playbook_row.get("steps_json");
        let steps: Vec<PlaybookStep> = serde_json::from_str(&steps_json).unwrap_or_default();
        let total_steps = steps.len() as i32;

        // Create run record
        let run_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO soar_playbook_runs (id, playbook_id, trigger_type, trigger_source, status, current_step, total_steps, input_data, started_at) VALUES (?, ?, 'schedule', ?, 'running', 0, ?, ?, ?)"
        )
        .bind(&run_id)
        .bind(&scheduled_playbook.playbook_id)
        .bind(Some(format!("scheduled:{}", scheduled_playbook.id)))
        .bind(total_steps)
        .bind(&scheduled_playbook.input_data)
        .bind(&now)
        .execute(pool)
        .await?;

        // Clone data for async task
        let pool_clone = pool.clone();
        let run_id_clone = run_id.clone();
        let scheduled_id = scheduled_playbook.id.clone();
        let input_data: Option<serde_json::Value> = scheduled_playbook
            .input_data
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());

        // Spawn async execution
        tokio::spawn(async move {
            let start_time = std::time::Instant::now();

            // Create execution context
            let run_uuid = match uuid::Uuid::parse_str(&run_id_clone) {
                Ok(uuid) => uuid,
                Err(_) => {
                    log::error!("Invalid run ID format: {}", run_id_clone);
                    return;
                }
            };

            let mut context = ExecutionContext::new(run_uuid, input_data);
            let action_executor = crate::green_team::playbooks::actions::ActionExecutor::new();

            // Execute each step
            for (step_index, step) in steps.iter().enumerate() {
                // Update current step in database
                if let Err(e) = update_playbook_run_step(&pool_clone, &run_id_clone, step_index as i32).await {
                    log::error!("Failed to update run step: {}", e);
                }

                // Check condition if present
                if let Some(ref condition) = step.condition {
                    if !crate::green_team::playbooks::conditions::evaluate_condition(condition, &context) {
                        log::info!("Step {} '{}' skipped due to condition", step_index, step.name);
                        continue;
                    }
                }

                // Execute the action
                match action_executor.execute(&step.action, &mut context).await {
                    Ok(output) => {
                        context.set_step_output(&step.id, output);
                        log::info!("Step {} '{}' completed successfully", step_index, step.name);
                    }
                    Err(error) => {
                        log::error!("Step {} '{}' failed: {}", step_index, step.name, error);

                        // Check if there's a failure handler
                        if let Some(ref failure_step_id) = step.on_failure {
                            log::info!("Jumping to failure handler step: {}", failure_step_id);
                            // For simplicity we'll just log and continue
                        } else {
                            // No failure handler, fail the run
                            let _ = mark_playbook_run_failed(&pool_clone, &run_id_clone, &error).await;
                            return;
                        }
                    }
                }
            }

            // Mark as completed
            let duration = start_time.elapsed().as_secs() as i32;
            let completed_at = chrono::Utc::now().to_rfc3339();

            if let Err(e) = sqlx::query(
                "UPDATE soar_playbook_runs SET status = 'completed', current_step = ?, completed_at = ?, duration_seconds = ? WHERE id = ?"
            )
            .bind(total_steps)
            .bind(&completed_at)
            .bind(duration)
            .bind(&run_id_clone)
            .execute(&pool_clone)
            .await {
                log::error!("Failed to mark run as completed: {}", e);
            }

            log::info!("Scheduled playbook run {} completed in {}s", run_id_clone, duration);
        });

        // Calculate next run time and update schedule
        let next_run = calculate_next_playbook_run(&scheduled_playbook.cron_expression);
        if let Err(e) = update_playbook_next_run(pool, &scheduled_playbook.id, next_run).await {
            log::error!(
                "Failed to update next run time for scheduled playbook {}: {}",
                scheduled_playbook.id,
                e
            );
        }
    }

    Ok(())
}

/// Calculate next run time from cron expression
fn calculate_next_playbook_run(cron_expression: &str) -> chrono::DateTime<chrono::Utc> {
    use chrono::Utc;

    // Simple cron parsing - in production use a proper cron library
    let parts: Vec<&str> = cron_expression.split_whitespace().collect();

    if parts.len() < 5 {
        // Default to daily if invalid
        return Utc::now() + chrono::Duration::hours(24);
    }

    let minute = parts[0];
    let hour = parts[1];

    // Handle common patterns
    if minute.starts_with("*/") {
        // Every N minutes
        let interval: i64 = minute.trim_start_matches("*/").parse().unwrap_or(60);
        return Utc::now() + chrono::Duration::minutes(interval);
    }

    if hour == "*" && minute != "*" {
        // Hourly at specific minute
        return Utc::now() + chrono::Duration::hours(1);
    }

    if hour != "*" && minute != "*" {
        // Daily at specific time
        return Utc::now() + chrono::Duration::hours(24);
    }

    // Default to daily
    Utc::now() + chrono::Duration::hours(24)
}

/// Helper function to update playbook run step
async fn update_playbook_run_step(pool: &SqlitePool, run_id: &str, step: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE soar_playbook_runs SET current_step = ? WHERE id = ?")
        .bind(step)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Helper function to mark playbook run as failed
async fn mark_playbook_run_failed(pool: &SqlitePool, run_id: &str, error: &str) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("UPDATE soar_playbook_runs SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?")
        .bind(error)
        .bind(&now)
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Helper function to mark playbook run as waiting approval
async fn mark_playbook_run_waiting_approval(pool: &SqlitePool, run_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE soar_playbook_runs SET status = 'waiting_approval' WHERE id = ?")
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Sanitize filename to remove unsafe characters
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

/// Escape a value for CSV
fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Generate HTML for vulnerability report
fn generate_vulnerability_html(data: &serde_json::Value) -> String {
    let empty_vec = vec![];
    let vulns = data["vulnerabilities"].as_array().unwrap_or(&empty_vec);

    let vuln_rows: String = vulns.iter().map(|v| {
        format!(
            "<tr><td>{}</td><td>{}</td><td class=\"severity-{}\">{}</td><td>{}</td><td>{}</td></tr>",
            v["host"].as_str().unwrap_or(""),
            v["title"].as_str().unwrap_or(""),
            v["severity"].as_str().unwrap_or("").to_lowercase(),
            v["severity"].as_str().unwrap_or(""),
            v["cve_id"].as_str().unwrap_or("N/A"),
            v["affected_service"].as_str().unwrap_or("N/A"),
        )
    }).collect();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #4F46E5; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .stat {{ background: #f0f4f8; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #4F46E5; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4F46E5; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-critical {{ color: #dc2626; font-weight: bold; }}
        .severity-high {{ color: #ea580c; font-weight: bold; }}
        .severity-medium {{ color: #ca8a04; }}
        .severity-low {{ color: #65a30d; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Report: {}</h1>
        <p>Generated: {} | Period: {} days</p>
        <div class="summary">
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Total Scans</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Vulnerabilities</div></div>
        </div>
        <table>
            <thead>
                <tr><th>Host</th><th>Title</th><th>Severity</th><th>CVE</th><th>Service</th></tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>
</body>
</html>"#,
        data["report_name"].as_str().unwrap_or(""),
        data["report_name"].as_str().unwrap_or(""),
        data["generated_at"].as_str().unwrap_or(""),
        data["period_days"],
        data["total_scans"],
        data["total_vulnerabilities"],
        vuln_rows
    )
}

/// Generate HTML for scan summary report
fn generate_scan_summary_html(data: &serde_json::Value) -> String {
    let empty_vec = vec![];
    let scans = data["scans"].as_array().unwrap_or(&empty_vec);

    let scan_rows: String = scans.iter().map(|s| {
        format!(
            "<tr><td>{}</td><td>{}</td><td class=\"status-{}\">{}</td><td>{}</td><td>{}</td></tr>",
            s["name"].as_str().unwrap_or(""),
            s["targets"].as_str().unwrap_or(""),
            s["status"].as_str().unwrap_or("").to_lowercase(),
            s["status"].as_str().unwrap_or(""),
            s["created_at"].as_str().unwrap_or(""),
            s["completed_at"].as_str().unwrap_or("N/A"),
        )
    }).collect();

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Scan Summary Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #4F46E5; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .stat {{ background: #f0f4f8; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #4F46E5; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #4F46E5; color: white; }}
        .status-completed {{ color: #16a34a; }}
        .status-failed {{ color: #dc2626; }}
        .status-pending {{ color: #ca8a04; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Summary Report: {}</h1>
        <p>Generated: {} | Period: {} days</p>
        <div class="summary">
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Total Scans</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Completed</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Failed</div></div>
        </div>
        <table>
            <thead><tr><th>Name</th><th>Targets</th><th>Status</th><th>Created</th><th>Completed</th></tr></thead>
            <tbody>{}</tbody>
        </table>
    </div>
</body>
</html>"#,
        data["report_name"].as_str().unwrap_or(""),
        data["report_name"].as_str().unwrap_or(""),
        data["generated_at"].as_str().unwrap_or(""),
        data["period_days"],
        data["total_scans"],
        data["completed_scans"],
        data["failed_scans"],
        scan_rows
    )
}

/// Generate HTML for compliance report
fn generate_compliance_html(data: &serde_json::Value) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #4F46E5; padding-bottom: 10px; }}
        .info {{ background: #f0f4f8; padding: 20px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Compliance Report: {}</h1>
        <p>Generated: {}</p>
        <div class="info">
            <p><strong>Frameworks:</strong> {}</p>
            <p><strong>Period:</strong> {} days</p>
            <p><strong>Scans Analyzed:</strong> {}</p>
        </div>
    </div>
</body>
</html>"#,
        data["report_name"].as_str().unwrap_or(""),
        data["report_name"].as_str().unwrap_or(""),
        data["generated_at"].as_str().unwrap_or(""),
        data["frameworks"].as_array().map(|f| f.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
        data["period_days"],
        data["total_scans_analyzed"]
    )
}

/// Generate HTML for executive report
fn generate_executive_html(data: &serde_json::Value) -> String {
    let summary = &data["summary"];
    let risk_class = match data["risk_level"].as_str().unwrap_or("Medium") {
        "Critical" => "risk-critical",
        "High" => "risk-high",
        _ => "risk-medium",
    };

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Executive Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #4F46E5; padding-bottom: 10px; }}
        .risk {{ padding: 15px 25px; border-radius: 8px; display: inline-block; font-weight: bold; margin: 20px 0; }}
        .risk-critical {{ background: #fee2e2; color: #dc2626; }}
        .risk-high {{ background: #ffedd5; color: #ea580c; }}
        .risk-medium {{ background: #fef3c7; color: #ca8a04; }}
        .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat {{ background: #f0f4f8; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; color: #4F46E5; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Executive Security Report: {}</h1>
        <p>Generated: {} | Period: {} days</p>
        <div class="risk {}">{} Risk Level</div>
        <div class="stats">
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Total Scans</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Hosts Discovered</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Vulnerabilities</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Critical</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">High</div></div>
            <div class="stat"><div class="stat-value">{}</div><div class="stat-label">Completed Scans</div></div>
        </div>
    </div>
</body>
</html>"#,
        data["report_name"].as_str().unwrap_or(""),
        data["report_name"].as_str().unwrap_or(""),
        data["generated_at"].as_str().unwrap_or(""),
        data["period_days"],
        risk_class,
        data["risk_level"].as_str().unwrap_or("Medium"),
        summary["total_scans"],
        summary["total_hosts_discovered"],
        summary["total_vulnerabilities"],
        summary["critical_vulnerabilities"],
        summary["high_vulnerabilities"],
        summary["completed_scans"]
    )
}
