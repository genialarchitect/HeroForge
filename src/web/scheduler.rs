//! Background scheduler for executing scheduled scans
//!
//! This module provides a background task that periodically checks for
//! scheduled scans that are due and executes them automatically.
//!
//! Production features:
//! - Retry logic with exponential backoff
//! - Email notifications for scan completion and failures
//! - Execution history tracking
//! - Jitter to prevent thundering herd

use crate::db::{self, models};
use crate::email::{EmailConfig, EmailService, ScanSummary};
use crate::scanner;
use crate::types::{HostInfo, OutputFormat, ScanConfig, ScanProgressMessage, ScanType};
use crate::web::broadcast;
use anyhow::Result;
use rand::Rng;
use sqlx::SqlitePool;
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
                log::error!("Scheduler error: {}", e);
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
