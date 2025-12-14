//! Background scheduler for executing scheduled scans
//!
//! This module provides a background task that periodically checks for
//! scheduled scans that are due and executes them automatically.

use crate::db::{self, models};
use crate::scanner;
use crate::types::{OutputFormat, ScanConfig, ScanProgressMessage, ScanType};
use crate::web::broadcast;
use anyhow::Result;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;

/// Default interval between scheduler checks (60 seconds)
const SCHEDULER_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Start the background scheduler daemon
///
/// This spawns a background task that periodically checks for due scheduled scans
/// and executes them. The task runs indefinitely until the server shuts down.
pub fn start_scheduler(pool: Arc<SqlitePool>) {
    tokio::spawn(async move {
        log::info!("Scheduler daemon started - checking every {:?}", SCHEDULER_CHECK_INTERVAL);

        loop {
            // Wait for the check interval
            tokio::time::sleep(SCHEDULER_CHECK_INTERVAL).await;

            // Check and execute due scans
            if let Err(e) = check_and_execute_due_scans(&pool).await {
                log::error!("Scheduler error: {}", e);
            }
        }
    });
}

/// Check for due scheduled scans and execute them
async fn check_and_execute_due_scans(pool: &SqlitePool) -> Result<()> {
    // Get all due scheduled scans
    let due_scans = db::get_due_scheduled_scans(pool).await?;

    if due_scans.is_empty() {
        log::debug!("No scheduled scans due");
        return Ok(());
    }

    log::info!("Found {} scheduled scan(s) due for execution", due_scans.len());

    for scheduled_scan in due_scans {
        if let Err(e) = execute_scheduled_scan(pool, &scheduled_scan).await {
            log::error!(
                "Failed to execute scheduled scan '{}' ({}): {}",
                scheduled_scan.name,
                scheduled_scan.id,
                e
            );
        }
    }

    Ok(())
}

/// Execute a single scheduled scan
async fn execute_scheduled_scan(
    pool: &SqlitePool,
    scheduled_scan: &models::ScheduledScan,
) -> Result<()> {
    log::info!(
        "Executing scheduled scan '{}' ({})",
        scheduled_scan.name,
        scheduled_scan.id
    );

    // Parse the scan configuration
    let config: models::ScheduledScanConfig = serde_json::from_str(&scheduled_scan.config)?;

    // Create a scan record in the database
    let scan_name = format!("{} - {}", scheduled_scan.name, chrono::Utc::now().format("%Y-%m-%d %H:%M"));
    let scan = db::create_scan(pool, &scheduled_scan.user_id, &scan_name, &config.targets).await?;
    let scan_id = scan.id.clone();

    // Build the scan configuration
    let scan_config = build_scan_config(&config)?;

    // Clone pool for the spawned task
    let pool_clone = pool.clone();
    let scheduled_scan_id = scheduled_scan.id.clone();

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

                log::info!(
                    "Scheduled scan '{}' completed - found {} hosts in {:.2}s",
                    scan_id,
                    results.len(),
                    duration.as_secs_f64()
                );
            }
            Err(e) => {
                let error_msg = format!("Scan failed: {}", e);
                let _ = tx.send(ScanProgressMessage::Error {
                    message: error_msg.clone(),
                });
                let _ = db::update_scan_status(&pool_clone, &scan_id, "failed", None, Some(&error_msg)).await;

                log::error!("Scheduled scan '{}' failed: {}", scan_id, e);
            }
        }

        // Update the scheduled scan execution record
        if let Err(e) = db::update_scheduled_scan_execution(&pool_clone, &scheduled_scan_id, &scan_id).await {
            log::error!("Failed to update scheduled scan execution record: {}", e);
        }

        // Clean up broadcast channel after a delay
        tokio::time::sleep(Duration::from_secs(60)).await;
        broadcast::remove_scan_channel(&scan_id).await;
    });

    Ok(())
}

/// Build a ScanConfig from a ScheduledScanConfig
fn build_scan_config(config: &models::ScheduledScanConfig) -> Result<ScanConfig> {
    use crate::scanner::enumeration::types::{EnumDepth, ServiceType, DbType};

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
    })
}
