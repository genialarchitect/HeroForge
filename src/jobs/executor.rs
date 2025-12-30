//! Job executor that processes jobs from the queue

use super::queue::JobQueue;
use super::types::{Job, JobType, JobResult, JobStatus};
use anyhow::{Result, Context};
use log::{debug, error, info, warn};
use std::sync::Arc;
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

                            // Spawn job execution
                            tokio::spawn(async move {
                                Self::execute_job_with_timeout(job, queue_clone, config_clone).await;
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
    ) {
        let job_timeout = Duration::from_secs(job.timeout_seconds);
        let job_id = job.id.clone();

        info!("Executing job {}: {:?}", job_id, job.job_type);

        let result = timeout(job_timeout, Self::execute_job(job.clone())).await;

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

    /// Execute a job (placeholder for actual job execution logic)
    async fn execute_job(job: Job) -> Result<JobResult> {
        match &job.job_type {
            JobType::Scan { scan_id, user_id } => {
                debug!("Executing scan job for scan_id: {}, user_id: {}", scan_id, user_id);
                // TODO: Integrate with actual scan execution
                // For now, return a placeholder
                Ok(JobResult::Success(format!("Scan {} completed", scan_id)))
            }

            JobType::Report { scan_id, format, user_id } => {
                debug!("Generating report for scan: {}, format: {}, user: {}", scan_id, format, user_id);
                // TODO: Integrate with report generation
                Ok(JobResult::Success(format!("Report generated for scan {}", scan_id)))
            }

            JobType::VulnRescan { vuln_ids, user_id } => {
                debug!("Rescanning {} vulnerabilities for user {}", vuln_ids.len(), user_id);
                // TODO: Integrate with vulnerability rescanning
                Ok(JobResult::Success(format!("Rescanned {} vulnerabilities", vuln_ids.len())))
            }

            JobType::DbCleanup { older_than_days } => {
                debug!("Running database cleanup for data older than {} days", older_than_days);
                // TODO: Integrate with database cleanup
                Ok(JobResult::Success(format!("Cleaned up data older than {} days", older_than_days)))
            }

            JobType::EmailNotification { to, subject, body } => {
                debug!("Sending email to: {}, subject: {}", to, subject);
                // TODO: Integrate with email module
                Ok(JobResult::Success(format!("Email sent to {}", to)))
            }

            JobType::WebhookDelivery { webhook_id, event_type, payload } => {
                debug!("Delivering webhook {} for event: {}", webhook_id, event_type);
                // TODO: Integrate with webhook delivery
                Ok(JobResult::Success(format!("Webhook {} delivered", webhook_id)))
            }

            JobType::ScheduledScan { scheduled_scan_id, user_id } => {
                debug!("Executing scheduled scan: {}, user: {}", scheduled_scan_id, user_id);
                // TODO: Integrate with scheduled scan execution
                Ok(JobResult::Success(format!("Scheduled scan {} executed", scheduled_scan_id)))
            }

            JobType::SiemExport { scan_id, integration_id } => {
                debug!("Exporting scan {} to SIEM integration {}", scan_id, integration_id);
                // TODO: Integrate with SIEM export
                Ok(JobResult::Success(format!("Exported scan {} to SIEM", scan_id)))
            }

            JobType::AssetDiscovery { user_id, network_ranges } => {
                debug!("Discovering assets for user {} in ranges: {:?}", user_id, network_ranges);
                // TODO: Integrate with asset discovery
                Ok(JobResult::Success(format!("Discovered assets in {} ranges", network_ranges.len())))
            }

            JobType::ComplianceReport { scan_id, framework, user_id } => {
                debug!("Generating compliance report for scan: {}, framework: {}, user: {}", scan_id, framework, user_id);
                // TODO: Integrate with compliance reporting
                Ok(JobResult::Success(format!("Compliance report generated for {}", framework)))
            }

            JobType::Backup { backup_type, destination } => {
                debug!("Running backup: type={}, destination={}", backup_type, destination);
                // TODO: Integrate with backup system
                Ok(JobResult::Success(format!("Backup completed to {}", destination)))
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
