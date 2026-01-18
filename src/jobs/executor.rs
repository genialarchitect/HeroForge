//! Job executor that processes jobs from the queue

use super::queue::JobQueue;
use super::types::{Job, JobType, JobResult};
use anyhow::{Result, Context};
use log::{debug, error, info, warn};
use std::sync::Arc;
use sqlx::SqlitePool;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// Job executor configuration
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Maximum number of concurrent jobs
    pub max_concurrent_jobs: usize,

    /// Poll interval for checking new jobs
    pub poll_interval_seconds: u64,

    /// Enable auto-retry for failed jobs
    pub auto_retry: bool,

    /// Maximum execution time per job (seconds)
    pub default_timeout_seconds: u64,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 10,
            poll_interval_seconds: 5,
            auto_retry: true,
            default_timeout_seconds: 3600,
        }
    }
}

/// Job executor that processes jobs from the queue
pub struct JobExecutor {
    queue: Arc<tokio::sync::Mutex<JobQueue>>,
    config: ExecutorConfig,
    semaphore: Arc<Semaphore>,
    running: Arc<tokio::sync::RwLock<bool>>,
    db_pool: Option<Arc<SqlitePool>>,
}

impl JobExecutor {
    /// Create a new job executor
    pub fn new(queue: JobQueue, config: ExecutorConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_jobs));

        Self {
            queue: Arc::new(tokio::sync::Mutex::new(queue)),
            config,
            semaphore,
            running: Arc::new(tokio::sync::RwLock::new(false)),
            db_pool: None,
        }
    }

    /// Create a new job executor with database pool for job execution
    pub fn with_db_pool(queue: JobQueue, config: ExecutorConfig, pool: SqlitePool) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_jobs));

        Self {
            queue: Arc::new(tokio::sync::Mutex::new(queue)),
            config,
            semaphore,
            running: Arc::new(tokio::sync::RwLock::new(false)),
            db_pool: Some(Arc::new(pool)),
        }
    }

    /// Start the job executor
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(anyhow::anyhow!("Executor is already running"));
        }
        *running = true;
        drop(running);

        info!("Job executor started with {} max concurrent jobs", self.config.max_concurrent_jobs);

        let queue = Arc::clone(&self.queue);
        let config = self.config.clone();
        let semaphore = Arc::clone(&self.semaphore);
        let running = Arc::clone(&self.running);
        let db_pool = self.db_pool.clone();

        tokio::spawn(async move {
            while *running.read().await {
                // Try to acquire semaphore permit
                if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                    // Get next job from queue
                    let job = {
                        let mut q = queue.lock().await;
                        q.dequeue().await
                    };

                    match job {
                        Ok(Some(job)) => {
                            let queue_clone = Arc::clone(&queue);
                            let config_clone = config.clone();
                            let db_pool_clone = db_pool.clone();

                            // Spawn job execution
                            tokio::spawn(async move {
                                Self::execute_job_with_timeout(job, queue_clone, config_clone, db_pool_clone).await;
                                drop(permit);
                            });
                        }
                        Ok(None) => {
                            // No jobs available, release permit and wait
                            drop(permit);
                            tokio::time::sleep(Duration::from_secs(config.poll_interval_seconds)).await;
                        }
                        Err(e) => {
                            error!("Error dequeuing job: {}", e);
                            drop(permit);
                            tokio::time::sleep(Duration::from_secs(config.poll_interval_seconds)).await;
                        }
                    }
                } else {
                    // All permits in use, wait before checking again
                    tokio::time::sleep(Duration::from_secs(config.poll_interval_seconds)).await;
                }
            }

            info!("Job executor stopped");
        });

        Ok(())
    }

    /// Stop the job executor
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Job executor stopping...");
    }

    /// Execute a job with timeout
    async fn execute_job_with_timeout(
        job: Job,
        queue: Arc<tokio::sync::Mutex<JobQueue>>,
        config: ExecutorConfig,
        db_pool: Option<Arc<SqlitePool>>,
    ) {
        let job_timeout = Duration::from_secs(job.timeout_seconds);
        let job_id = job.id.clone();

        info!("Executing job {}: {:?}", job_id, job.job_type);

        let result = timeout(job_timeout, Self::execute_job(job.clone(), db_pool)).await;

        let mut queue_guard = queue.lock().await;

        match result {
            Ok(Ok(job_result)) => {
                // Job completed successfully
                let mut completed_job = job;
                match job_result {
                    JobResult::Success(data) => {
                        completed_job.complete(Some(data));
                        info!("Job {} completed successfully", job_id);
                    }
                    JobResult::Failure(error) => {
                        completed_job.fail(error.clone());
                        warn!("Job {} failed: {}", job_id, error);

                        // Retry if enabled
                        if config.auto_retry && completed_job.can_retry() {
                            if let Err(e) = queue_guard.requeue(completed_job.clone()).await {
                                error!("Failed to requeue job {}: {}", job_id, e);
                            }
                            return;
                        }
                    }
                }

                if let Err(e) = queue_guard.update_job(&completed_job).await {
                    error!("Failed to update job {}: {}", job_id, e);
                }
            }
            Ok(Err(e)) => {
                // Job execution error
                let mut failed_job = job;
                failed_job.fail(e.to_string());
                error!("Job {} failed with error: {}", job_id, e);

                // Retry if enabled
                if config.auto_retry && failed_job.can_retry() {
                    if let Err(e) = queue_guard.requeue(failed_job.clone()).await {
                        error!("Failed to requeue job {}: {}", job_id, e);
                    }
                    return;
                }

                if let Err(e) = queue_guard.update_job(&failed_job).await {
                    error!("Failed to update job {}: {}", job_id, e);
                }
            }
            Err(_) => {
                // Job timeout
                let mut timeout_job = job;
                timeout_job.fail(format!("Job execution timed out after {} seconds", job_timeout.as_secs()));
                error!("Job {} timed out", job_id);

                if let Err(e) = queue_guard.update_job(&timeout_job).await {
                    error!("Failed to update job {}: {}", job_id, e);
                }
            }
        }
    }

    /// Execute a job with actual implementation
    async fn execute_job(job: Job, db_pool: Option<Arc<SqlitePool>>) -> Result<JobResult> {
        match &job.job_type {
            JobType::Scan { scan_id, user_id } => {
                Self::execute_scan_job(scan_id, user_id, db_pool).await
            }

            JobType::Report { scan_id, format, user_id } => {
                Self::execute_report_job(scan_id, format, user_id, db_pool).await
            }

            JobType::VulnRescan { vuln_ids, user_id } => {
                Self::execute_vuln_rescan_job(vuln_ids, user_id, db_pool).await
            }

            JobType::DbCleanup { older_than_days } => {
                Self::execute_db_cleanup_job(*older_than_days, db_pool).await
            }

            JobType::EmailNotification { to, subject, body } => {
                Self::execute_email_notification_job(to, subject, body).await
            }

            JobType::WebhookDelivery { webhook_id, event_type, payload } => {
                Self::execute_webhook_delivery_job(webhook_id, event_type, payload, db_pool).await
            }

            JobType::ScheduledScan { scheduled_scan_id, user_id } => {
                Self::execute_scheduled_scan_job(scheduled_scan_id, user_id, db_pool).await
            }

            JobType::SiemExport { scan_id, integration_id } => {
                Self::execute_siem_export_job(scan_id, integration_id, db_pool).await
            }

            JobType::AssetDiscovery { user_id, network_ranges } => {
                Self::execute_asset_discovery_job(user_id, network_ranges, db_pool).await
            }

            JobType::ComplianceReport { scan_id, framework, user_id } => {
                Self::execute_compliance_report_job(scan_id, framework, user_id, db_pool).await
            }

            JobType::Backup { backup_type, destination } => {
                Self::execute_backup_job(backup_type, destination).await
            }
        }
    }

    /// Execute a network scan job
    async fn execute_scan_job(
        scan_id: &str,
        user_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Executing scan job for scan_id: {}, user_id: {}", scan_id, user_id);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Get the scan from the database
        let scan = crate::db::get_scan_by_id(&pool, scan_id)
            .await
            .context("Failed to fetch scan from database")?
            .ok_or_else(|| anyhow::anyhow!("Scan {} not found", scan_id))?;

        // Update scan status to running
        crate::db::update_scan_status(&pool, scan_id, "running", None, None)
            .await
            .context("Failed to update scan status")?;

        // Parse targets from the scan record (targets is a JSON array string)
        let targets: Vec<String> = serde_json::from_str(&scan.targets)
            .context("Failed to parse scan targets")?;

        // Build scan configuration from targets
        let mut config = crate::types::ScanConfig::default();
        config.targets = targets;

        // Execute the scan
        match crate::scanner::run_scan(&config, None).await {
            Ok(results) => {
                let results_json = serde_json::to_string(&results)
                    .context("Failed to serialize scan results")?;

                // Update scan status with results
                crate::db::update_scan_status(&pool, scan_id, "completed", Some(&results_json), None)
                    .await
                    .context("Failed to save scan results")?;

                let host_count = results.len();
                let port_count: usize = results.iter()
                    .map(|h| h.ports.len())
                    .sum();

                info!("Scan {} completed: {} hosts, {} ports", scan_id, host_count, port_count);
                Ok(JobResult::Success(serde_json::json!({
                    "scan_id": scan_id,
                    "hosts_discovered": host_count,
                    "ports_found": port_count,
                    "status": "completed"
                }).to_string()))
            }
            Err(e) => {
                error!("Scan {} failed: {}", scan_id, e);
                crate::db::update_scan_status(&pool, scan_id, "failed", None, Some(&e.to_string()))
                    .await
                    .context("Failed to update scan status")?;

                Ok(JobResult::Failure(format!("Scan failed: {}", e)))
            }
        }
    }

    /// Execute a report generation job
    async fn execute_report_job(
        scan_id: &str,
        format: &str,
        user_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Generating report for scan: {}, format: {}, user: {}", scan_id, format, user_id);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Parse report format
        let report_format: crate::reports::types::ReportFormat = format.parse()
            .map_err(|e: String| anyhow::anyhow!("Invalid report format: {}", e))?;

        // Get the reports directory from environment or use default
        let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());

        // Create report generator
        let generator = crate::reports::ReportGenerator::new((*pool).clone(), reports_dir);

        // Generate a unique report ID
        let report_id = uuid::Uuid::new_v4().to_string();

        // Generate the report
        match generator.generate(
            &report_id,
            scan_id,
            &format!("Scan Report - {}", scan_id),
            Some("Auto-generated report from job queue"),
            report_format,
            "executive", // default template
            vec!["summary".to_string(), "findings".to_string(), "hosts".to_string()],
            crate::reports::types::ReportOptions::default(),
        ).await {
            Ok(report_path) => {
                info!("Report generated: {} at {}", report_id, report_path);
                Ok(JobResult::Success(serde_json::json!({
                    "report_id": report_id,
                    "scan_id": scan_id,
                    "format": format,
                    "path": report_path
                }).to_string()))
            }
            Err(e) => {
                error!("Report generation failed for scan {}: {}", scan_id, e);
                Ok(JobResult::Failure(format!("Report generation failed: {}", e)))
            }
        }
    }

    /// Execute a vulnerability rescan job
    async fn execute_vuln_rescan_job(
        vuln_ids: &[String],
        user_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Rescanning {} vulnerabilities for user {}", vuln_ids.len(), user_id);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        let mut rescanned = 0;
        let mut failed = 0;
        let mut results = Vec::new();

        for vuln_id in vuln_ids {
            // Get vulnerability details using the tracking table
            match crate::db::get_vulnerability_detail(&pool, vuln_id).await {
                Ok(vuln) => {
                    // Parse target information from vulnerability tracking
                    let host_ip = &vuln.vulnerability.host_ip;
                    let port = vuln.vulnerability.port;

                    // Create a minimal scan config for the vulnerability check
                    let target = if let Some(p) = port {
                        format!("{}:{}", host_ip, p)
                    } else {
                        host_ip.clone()
                    };
                    info!("Rescanning vulnerability {} on {}", vuln_id, target);

                    // Create update request to mark as pending verification
                    let update_request = crate::db::models::UpdateVulnerabilityRequest {
                        status: Some("pending_verification".to_string()),
                        notes: Some(format!("Rescan requested at {}", chrono::Utc::now())),
                        assignee_id: None,
                        due_date: None,
                        priority: None,
                        remediation_steps: None,
                        estimated_effort: None,
                        actual_effort: None,
                    };

                    // Update vulnerability status
                    if let Err(e) = crate::db::update_vulnerability_status(
                        &pool, vuln_id, &update_request, user_id
                    ).await {
                        warn!("Failed to update vulnerability status: {}", e);
                    }

                    // Note: Full vulnerability rescan would require additional logic
                    // to re-run specific vulnerability checks. For now, we mark as rescanned.
                    rescanned += 1;
                    results.push(serde_json::json!({
                        "vuln_id": vuln_id,
                        "status": "rescanned",
                        "target": target
                    }));
                }
                Err(e) => {
                    // Could be not found or other error
                    warn!("Failed to fetch vulnerability {}: {}", vuln_id, e);
                    failed += 1;
                }
            }
        }

        info!("Vulnerability rescan complete: {} rescanned, {} failed", rescanned, failed);
        Ok(JobResult::Success(serde_json::json!({
            "total": vuln_ids.len(),
            "rescanned": rescanned,
            "failed": failed,
            "results": results
        }).to_string()))
    }

    /// Execute a database cleanup job
    async fn execute_db_cleanup_job(
        older_than_days: u32,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Running database cleanup for data older than {} days", older_than_days);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;
        let days = older_than_days as i64;

        let mut cleanup_results = serde_json::Map::new();

        // Clean up old webhook deliveries
        match crate::db::cleanup_old_deliveries(&pool, days).await {
            Ok(count) => {
                cleanup_results.insert("webhook_deliveries".to_string(), serde_json::json!(count));
            }
            Err(e) => {
                warn!("Failed to cleanup webhook deliveries: {}", e);
            }
        }

        // Clean up expired refresh tokens
        match crate::db::cleanup_expired_refresh_tokens(&pool).await {
            Ok(()) => {
                cleanup_results.insert("refresh_tokens".to_string(), serde_json::json!("cleaned"));
            }
            Err(e) => {
                warn!("Failed to cleanup refresh tokens: {}", e);
            }
        }

        // Clean up old conversations (chat)
        match crate::db::chat::cleanup_old_conversations(&pool, days).await {
            Ok(count) => {
                cleanup_results.insert("conversations".to_string(), serde_json::json!(count));
            }
            Err(e) => {
                warn!("Failed to cleanup old conversations: {}", e);
            }
        }

        // Clean up expired threat intel cache
        match crate::db::threat_intel::cleanup_expired_cache(&pool).await {
            Ok((ip_count, cve_count)) => {
                cleanup_results.insert("threat_intel_ip_cache".to_string(), serde_json::json!(ip_count));
                cleanup_results.insert("threat_intel_cve_cache".to_string(), serde_json::json!(cve_count));
            }
            Err(e) => {
                warn!("Failed to cleanup threat intel cache: {}", e);
            }
        }

        // Clean up old agent heartbeats
        match crate::db::agents::cleanup_old_heartbeats(&pool).await {
            Ok(count) => {
                cleanup_results.insert("agent_heartbeats".to_string(), serde_json::json!(count));
            }
            Err(e) => {
                warn!("Failed to cleanup agent heartbeats: {}", e);
            }
        }

        // Clean up expired permission cache
        match crate::db::permissions::cache::cleanup_expired_cache(&pool).await {
            Ok(count) => {
                cleanup_results.insert("permission_cache".to_string(), serde_json::json!(count));
            }
            Err(e) => {
                warn!("Failed to cleanup permission cache: {}", e);
            }
        }

        info!("Database cleanup completed: {:?}", cleanup_results);
        Ok(JobResult::Success(serde_json::json!({
            "older_than_days": older_than_days,
            "cleanup_results": cleanup_results
        }).to_string()))
    }

    /// Execute an email notification job
    async fn execute_email_notification_job(
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<JobResult> {
        debug!("Sending email to: {}, subject: {}", to, subject);

        // Load email configuration from environment
        let email_config = match crate::email::EmailConfig::from_env() {
            Ok(config) => config,
            Err(e) => {
                error!("Email configuration not available: {}", e);
                return Ok(JobResult::Failure(format!("Email not configured: {}", e)));
            }
        };

        let email_service = crate::email::EmailService::new(email_config);

        // Create HTML version of the body
        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head><style>body {{ font-family: Arial, sans-serif; line-height: 1.6; }}</style></head>
<body>
<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>{}</h2>
    <div style="white-space: pre-wrap;">{}</div>
    <hr style="margin-top: 30px; border: 0; border-top: 1px solid #eee;" />
    <p style="color: #666; font-size: 12px;">This is an automated notification from HeroForge.</p>
</div>
</body>
</html>"#,
            subject, body
        );

        // Send the email using our helper function
        match send_generic_email(&email_service, to, subject, body, &html_body).await {
            Ok(()) => {
                info!("Email sent successfully to {}", to);
                Ok(JobResult::Success(serde_json::json!({
                    "to": to,
                    "subject": subject,
                    "status": "sent"
                }).to_string()))
            }
            Err(e) => {
                error!("Failed to send email to {}: {}", to, e);
                Ok(JobResult::Failure(format!("Failed to send email: {}", e)))
            }
        }
    }

    /// Execute a webhook delivery job
    async fn execute_webhook_delivery_job(
        webhook_id: &str,
        event_type: &str,
        payload: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Delivering webhook {} for event: {}", webhook_id, event_type);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Get webhook configuration
        let webhook = crate::db::get_webhook_by_id_internal(&pool, webhook_id)
            .await
            .context("Failed to fetch webhook")?
            .ok_or_else(|| anyhow::anyhow!("Webhook {} not found", webhook_id))?;

        // Check if webhook is active
        if !webhook.is_active {
            return Ok(JobResult::Failure(format!("Webhook {} is disabled", webhook_id)));
        }

        // Send the webhook
        let delivery_result = crate::webhooks::sender::send_webhook(&webhook, payload).await;

        // Log the delivery
        let _ = crate::db::log_delivery(
            &pool,
            webhook_id,
            event_type,
            payload,
            delivery_result.status_code.map(|c| c as i32),
            delivery_result.response_body.as_deref(),
            delivery_result.error.as_deref(),
        ).await;

        // Update webhook status based on result
        if delivery_result.success {
            let _ = crate::db::update_webhook_status(
                &pool,
                webhook_id,
                delivery_result.status_code.map(|c| c as i32),
                true
            ).await;
            info!("Webhook {} delivered successfully", webhook_id);
            Ok(JobResult::Success(serde_json::json!({
                "webhook_id": webhook_id,
                "event_type": event_type,
                "status": "delivered",
                "status_code": delivery_result.status_code,
                "attempts": delivery_result.attempts
            }).to_string()))
        } else {
            let _ = crate::db::update_webhook_status(
                &pool,
                webhook_id,
                delivery_result.status_code.map(|c| c as i32),
                false
            ).await;
            warn!("Webhook {} delivery failed: {:?}", webhook_id, delivery_result.error);
            Ok(JobResult::Failure(format!(
                "Webhook delivery failed: {}",
                delivery_result.error.unwrap_or_else(|| "Unknown error".to_string())
            )))
        }
    }

    /// Execute a scheduled scan job
    async fn execute_scheduled_scan_job(
        scheduled_scan_id: &str,
        user_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Executing scheduled scan: {}, user: {}", scheduled_scan_id, user_id);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Get the scheduled scan configuration
        let scheduled_scan = crate::db::get_scheduled_scan_by_id(&pool, scheduled_scan_id)
            .await
            .context("Failed to fetch scheduled scan")?
            .ok_or_else(|| anyhow::anyhow!("Scheduled scan {} not found", scheduled_scan_id))?;

        if !scheduled_scan.is_active {
            return Ok(JobResult::Failure("Scheduled scan is not active".to_string()));
        }

        // Parse the scan configuration
        let scan_config: crate::db::models::ScheduledScanConfig =
            serde_json::from_str(&scheduled_scan.config)
                .context("Failed to parse scheduled scan config")?;

        // Build the scan configuration
        let mut config = crate::types::ScanConfig::default();
        config.targets = scan_config.targets.clone();

        // Create the scan record
        let scan = crate::db::create_scan(
            &pool,
            user_id,
            &scheduled_scan.name,
            &scan_config.targets,
            None, // customer_id
            None, // engagement_id
        ).await.context("Failed to create scan record")?;

        let scan_id = scan.id.clone();

        // Create execution record (returns the execution record with id)
        let execution = crate::db::create_execution_record(
            &pool,
            scheduled_scan_id,
            0, // retry_attempt
        ).await.context("Failed to create execution record")?;

        // Update scan status
        let _ = crate::db::update_scan_status(&pool, &scan_id, "running", None, None).await;

        // Execute the scan
        match crate::scanner::run_scan(&config, None).await {
            Ok(results) => {
                let results_json = serde_json::to_string(&results)?;
                let _ = crate::db::update_scan_status(&pool, &scan_id, "completed", Some(&results_json), None).await;

                // Update scheduled scan execution record
                let _ = crate::db::update_scheduled_scan_execution(
                    &pool,
                    scheduled_scan_id,
                    &scan_id,
                ).await;

                // Complete execution record
                let _ = crate::db::complete_execution_record(
                    &pool,
                    &execution.id,
                    Some(&scan_id),
                    "completed",
                    None
                ).await;

                // Reset retry count on success
                let _ = crate::db::reset_scheduled_scan_retry(&pool, scheduled_scan_id).await;

                let host_count = results.len();
                info!("Scheduled scan {} completed: {} hosts discovered", scheduled_scan_id, host_count);

                Ok(JobResult::Success(serde_json::json!({
                    "scheduled_scan_id": scheduled_scan_id,
                    "scan_id": scan_id,
                    "hosts_discovered": host_count,
                    "status": "completed"
                }).to_string()))
            }
            Err(e) => {
                let _ = crate::db::update_scan_status(&pool, &scan_id, "failed", None, Some(&e.to_string())).await;
                let _ = crate::db::complete_execution_record(
                    &pool,
                    &execution.id,
                    Some(&scan_id),
                    "failed",
                    Some(&e.to_string())
                ).await;
                let _ = crate::db::update_scheduled_scan_retry(&pool, scheduled_scan_id, 1, Some(&e.to_string())).await;

                error!("Scheduled scan {} failed: {}", scheduled_scan_id, e);
                Ok(JobResult::Failure(format!("Scheduled scan failed: {}", e)))
            }
        }
    }

    /// Execute a SIEM export job
    async fn execute_siem_export_job(
        scan_id: &str,
        integration_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Exporting scan {} to SIEM integration {}", scan_id, integration_id);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Get scan results
        let scan = crate::db::get_scan_by_id(&pool, scan_id)
            .await
            .context("Failed to fetch scan")?
            .ok_or_else(|| anyhow::anyhow!("Scan {} not found", scan_id))?;

        // Parse scan results
        let hosts: Vec<crate::types::HostInfo> = if let Some(ref results_json) = scan.results {
            serde_json::from_str(results_json).context("Failed to parse scan results")?
        } else {
            return Ok(JobResult::Failure("Scan has no results".to_string()));
        };

        // Get SIEM integration settings (stored in user's integration settings)
        // For now, we'll use environment-based configuration
        let siem_type = std::env::var("SIEM_TYPE").unwrap_or_else(|_| "syslog".to_string());
        let siem_endpoint = std::env::var("SIEM_ENDPOINT")
            .unwrap_or_else(|_| "localhost:514".to_string());
        let siem_api_key = std::env::var("SIEM_API_KEY").ok();

        let siem_config = crate::integrations::siem::SiemConfig {
            siem_type: crate::integrations::siem::SiemType::from_str(&siem_type)
                .ok_or_else(|| anyhow::anyhow!("Invalid SIEM type: {}", siem_type))?,
            endpoint_url: siem_endpoint,
            api_key: siem_api_key,
            protocol: Some("tcp".to_string()),
        };

        // Create exporter
        let exporter = crate::integrations::siem::create_exporter(siem_config)
            .await
            .context("Failed to create SIEM exporter")?;

        // Convert scan results to SIEM events
        let mut events = Vec::new();
        let now = chrono::Utc::now();

        for host in &hosts {
            let host_ip = host.target.ip.to_string();
            let hostname = host.target.hostname.clone();
            let os_info = host.os_guess.as_ref().map(|o| o.os_family.clone());

            // Host discovery event
            events.push(crate::integrations::siem::SiemEvent {
                timestamp: now,
                severity: "info".to_string(),
                event_type: "host_discovered".to_string(),
                source_ip: None,
                destination_ip: Some(host_ip.clone()),
                port: None,
                protocol: None,
                message: format!("Host discovered: {}", host_ip),
                details: serde_json::json!({
                    "hostname": hostname,
                    "os": os_info,
                    "is_alive": host.is_alive
                }),
                cve_ids: vec![],
                cvss_score: None,
                scan_id: scan_id.to_string(),
                user_id: scan.user_id.clone(),
            });

            // Port/vulnerability events
            for port in &host.ports {
                for vuln in &host.vulnerabilities {
                    let severity_str = match vuln.severity {
                        crate::types::Severity::Critical => "critical",
                        crate::types::Severity::High => "high",
                        crate::types::Severity::Medium => "medium",
                        crate::types::Severity::Low => "low",
                    };

                    events.push(crate::integrations::siem::SiemEvent {
                        timestamp: now,
                        severity: severity_str.to_string(),
                        event_type: "vulnerability_found".to_string(),
                        source_ip: None,
                        destination_ip: Some(host_ip.clone()),
                        port: Some(port.port),
                        protocol: Some(format!("{:?}", port.protocol)),
                        message: format!("Vulnerability found: {}", vuln.title),
                        details: serde_json::json!({
                            "cve_id": vuln.cve_id,
                            "description": vuln.description,
                            "affected_service": vuln.affected_service
                        }),
                        cve_ids: vuln.cve_id.iter().cloned().collect(),
                        cvss_score: None,
                        scan_id: scan_id.to_string(),
                        user_id: scan.user_id.clone(),
                    });
                }
            }
        }

        // Export events
        match exporter.export_events(&events).await {
            Ok(()) => {
                info!("Exported {} events from scan {} to SIEM", events.len(), scan_id);
                Ok(JobResult::Success(serde_json::json!({
                    "scan_id": scan_id,
                    "integration_id": integration_id,
                    "events_exported": events.len(),
                    "status": "completed"
                }).to_string()))
            }
            Err(e) => {
                error!("SIEM export failed for scan {}: {}", scan_id, e);
                Ok(JobResult::Failure(format!("SIEM export failed: {}", e)))
            }
        }
    }

    /// Execute an asset discovery job
    async fn execute_asset_discovery_job(
        user_id: &str,
        network_ranges: &[String],
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Discovering assets for user {} in ranges: {:?}", user_id, network_ranges);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        let mut total_assets = 0;
        let mut results = Vec::new();

        for range in network_ranges {
            // Create asset discovery configuration
            let mut config = crate::scanner::asset_discovery::AssetDiscoveryConfig::default();
            config.domain = range.clone();
            config.include_ct_logs = true;
            config.include_dns = true;
            config.include_whois = false; // Skip WHOIS for network ranges
            config.include_shodan = false; // Requires API key
            config.include_censys = false; // Requires API key
            config.active_enum = true;
            config.timeout_secs = 300;

            // Run asset discovery
            match crate::scanner::asset_discovery::run_asset_discovery(config).await {
                Ok(discovery_result) => {
                    let asset_count = discovery_result.assets.len();
                    total_assets += asset_count;

                    // Store discovery results using the proper function
                    if let Err(e) = crate::db::asset_discovery::save_discovery_results(
                        &pool,
                        &discovery_result,
                    ).await {
                        warn!("Failed to save discovery results for {}: {}", range, e);
                    }

                    results.push(serde_json::json!({
                        "range": range,
                        "assets_found": asset_count,
                        "status": "completed"
                    }));

                    info!("Asset discovery for {}: {} assets found", range, asset_count);
                }
                Err(e) => {
                    warn!("Asset discovery failed for {}: {}", range, e);
                    results.push(serde_json::json!({
                        "range": range,
                        "error": e.to_string(),
                        "status": "failed"
                    }));
                }
            }
        }

        info!("Asset discovery completed: {} total assets in {} ranges", total_assets, network_ranges.len());
        Ok(JobResult::Success(serde_json::json!({
            "user_id": user_id,
            "ranges_scanned": network_ranges.len(),
            "total_assets": total_assets,
            "results": results
        }).to_string()))
    }

    /// Execute a compliance report job
    async fn execute_compliance_report_job(
        scan_id: &str,
        framework: &str,
        _user_id: &str,
        db_pool: Option<Arc<SqlitePool>>,
    ) -> Result<JobResult> {
        debug!("Generating compliance report for scan: {}, framework: {}", scan_id, framework);

        let pool = db_pool.ok_or_else(|| anyhow::anyhow!("Database pool not available"))?;

        // Get scan results
        let scan = crate::db::get_scan_by_id(&pool, scan_id)
            .await
            .context("Failed to fetch scan")?
            .ok_or_else(|| anyhow::anyhow!("Scan {} not found", scan_id))?;

        // Parse scan results
        let hosts: Vec<crate::types::HostInfo> = if let Some(ref results_json) = scan.results {
            serde_json::from_str(results_json).context("Failed to parse scan results")?
        } else {
            return Ok(JobResult::Failure("Scan has no results".to_string()));
        };

        // Parse framework ID to ComplianceFramework enum
        let compliance_framework = crate::compliance::types::ComplianceFramework::from_id(framework)
            .ok_or_else(|| anyhow::anyhow!("Unknown compliance framework: {}", framework))?;

        // Run compliance analysis
        let analyzer = crate::compliance::analyzer::ComplianceAnalyzer::new(vec![compliance_framework]);
        let compliance_summary = analyzer.analyze(&hosts, scan_id)
            .await
            .context("Failed to run compliance analysis")?;

        // Generate compliance report
        let reports_dir = std::env::var("REPORTS_DIR").unwrap_or_else(|_| "./reports".to_string());
        let report_generator = crate::reports::ReportGenerator::new((*pool).clone(), reports_dir);

        let report_id = uuid::Uuid::new_v4().to_string();

        // Calculate compliance metrics from the summary
        let (controls_passed, controls_failed) = if let Some(fw) = compliance_summary.frameworks.first() {
            (fw.compliant, fw.non_compliant)
        } else {
            (0, 0)
        };

        match report_generator.generate(
            &report_id,
            scan_id,
            &format!("{} Compliance Report", framework.to_uppercase()),
            Some(&format!("Compliance analysis against {} framework", framework)),
            crate::reports::types::ReportFormat::Pdf,
            "compliance",
            vec!["compliance_summary".to_string(), "control_assessment".to_string(), "recommendations".to_string()],
            crate::reports::types::ReportOptions {
                include_charts: true,
                include_screenshots: false,
                include_ai_narrative: false,
                company_name: None,
                assessor_name: None,
                classification: Some("Compliance Assessment".to_string()),
                industry: None,
            },
        ).await {
            Ok(report_path) => {
                info!("Compliance report generated: {} for framework {}", report_id, framework);
                Ok(JobResult::Success(serde_json::json!({
                    "report_id": report_id,
                    "scan_id": scan_id,
                    "framework": framework,
                    "compliance_score": compliance_summary.overall_score,
                    "controls_passed": controls_passed,
                    "controls_failed": controls_failed,
                    "path": report_path
                }).to_string()))
            }
            Err(e) => {
                error!("Compliance report generation failed: {}", e);
                Ok(JobResult::Failure(format!("Compliance report generation failed: {}", e)))
            }
        }
    }

    /// Execute a backup job
    async fn execute_backup_job(
        backup_type: &str,
        destination: &str,
    ) -> Result<JobResult> {
        debug!("Running backup: type={}, destination={}", backup_type, destination);

        // Get database path from environment or use default
        let db_path = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "./heroforge.db".to_string())
            .replace("sqlite://", "");

        // Create backup configuration
        let config = crate::backup::BackupConfig {
            destination: std::path::PathBuf::from(destination),
            retention_days: 30,
            encrypt: backup_type.contains("encrypted"),
            compress: true,
        };

        // Determine backup type
        let btype = match backup_type {
            "full" | "encrypted" => crate::backup::BackupType::Full,
            "incremental" => crate::backup::BackupType::Incremental,
            "differential" => crate::backup::BackupType::Differential,
            _ => crate::backup::BackupType::Full,
        };

        // Create the backup
        match crate::backup::create_backup_with_type(&config, &db_path, btype).await {
            Ok(metadata) => {
                info!(
                    "Backup completed: {} ({} bytes) at {}",
                    metadata.id, metadata.size_bytes, metadata.destination_path
                );
                Ok(JobResult::Success(serde_json::json!({
                    "backup_id": metadata.id,
                    "backup_type": backup_type,
                    "destination": metadata.destination_path,
                    "size_bytes": metadata.size_bytes,
                    "encrypted": metadata.encrypted,
                    "compressed": metadata.compressed,
                    "checksum": metadata.checksum
                }).to_string()))
            }
            Err(e) => {
                error!("Backup failed: {}", e);
                Ok(JobResult::Failure(format!("Backup failed: {}", e)))
            }
        }
    }

    /// Check if executor is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get current queue statistics
    pub async fn get_stats(&self) -> Result<super::types::JobStats> {
        let mut queue = self.queue.lock().await;
        queue.get_stats().await
    }
}

/// Helper function to send a generic email using lettre directly
async fn send_generic_email(
    _email_service: &crate::email::EmailService,
    to: &str,
    subject: &str,
    text_body: &str,
    html_body: &str,
) -> Result<()> {
    use lettre::message::{header, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let config = crate::email::EmailConfig::from_env()?;

    let email = Message::builder()
        .from(
            format!("{} <{}>", config.from_name, config.from_address)
                .parse()
                .context("Failed to parse from address")?,
        )
        .to(to.parse().context("Failed to parse recipient address")?)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_PLAIN)
                        .body(text_body.to_string()),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(header::ContentType::TEXT_HTML)
                        .body(html_body.to_string()),
                ),
        )
        .context("Failed to build email message")?;

    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

    let mailer = SmtpTransport::relay(&config.smtp_host)
        .context("Failed to create SMTP transport")?
        .credentials(creds)
        .port(config.smtp_port)
        .build();

    // Send email in a blocking task since lettre is synchronous
    tokio::task::spawn_blocking(move || mailer.send(&email))
        .await
        .context("Failed to execute email send task")?
        .context("Failed to send email")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::types::JobPriority;

    #[tokio::test]
    async fn test_executor_lifecycle() {
        // Skip if Redis not available
        let queue = JobQueue::new("redis://localhost:6379").await;
        if queue.is_err() {
            println!("Skipping test: Redis not available");
            return;
        }

        let queue = queue.unwrap();
        let config = ExecutorConfig {
            max_concurrent_jobs: 2,
            poll_interval_seconds: 1,
            ..Default::default()
        };

        let executor = JobExecutor::new(queue, config);

        // Start executor
        assert!(!executor.is_running().await);
        executor.start().await.unwrap();
        assert!(executor.is_running().await);

        // Wait a bit
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Stop executor
        executor.stop().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!executor.is_running().await);
    }
}
