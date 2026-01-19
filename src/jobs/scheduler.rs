//! Cron-like job scheduler for recurring tasks

use super::queue::JobQueue;
use super::types::{Job, JobPriority, JobType};
use anyhow::{Result, Context};
use chrono::{DateTime, Utc};
use cron::Schedule;
use log::{debug, error, info};
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Scheduled job definition
#[derive(Debug, Clone)]
pub struct ScheduledJob {
    /// Unique identifier
    pub id: String,

    /// Job name/description
    pub name: String,

    /// Cron expression (e.g., "0 0 * * *" for daily at midnight)
    pub cron_expression: String,

    /// Job type and configuration
    pub job_type: JobType,

    /// Job priority
    pub priority: JobPriority,

    /// Whether the schedule is active
    pub is_active: bool,

    /// Next scheduled run time
    pub next_run: DateTime<Utc>,

    /// Last run time
    pub last_run: Option<DateTime<Utc>>,

    /// Timezone for schedule (defaults to UTC)
    pub timezone: String,
}

impl ScheduledJob {
    /// Create a new scheduled job
    pub fn new(
        name: String,
        cron_expression: String,
        job_type: JobType,
        priority: JobPriority,
    ) -> Result<Self> {
        // Validate cron expression
        Schedule::from_str(&cron_expression)
            .context("Invalid cron expression")?;

        let next_run = Self::calculate_next_run(&cron_expression)?;

        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            cron_expression,
            job_type,
            priority,
            is_active: true,
            next_run,
            last_run: None,
            timezone: "UTC".to_string(),
        })
    }

    /// Calculate next run time based on cron expression
    fn calculate_next_run(cron_expression: &str) -> Result<DateTime<Utc>> {
        let schedule = Schedule::from_str(cron_expression)
            .context("Invalid cron expression")?;

        let now = Utc::now();
        let next = schedule.upcoming(Utc).next()
            .ok_or_else(|| anyhow::anyhow!("No upcoming scheduled time"))?;

        Ok(next)
    }

    /// Update next run time
    pub fn update_next_run(&mut self) -> Result<()> {
        self.next_run = Self::calculate_next_run(&self.cron_expression)?;
        Ok(())
    }

    /// Mark as executed
    pub fn mark_executed(&mut self) -> Result<()> {
        self.last_run = Some(Utc::now());
        self.update_next_run()?;
        Ok(())
    }

    /// Check if job is due to run
    pub fn is_due(&self) -> bool {
        self.is_active && Utc::now() >= self.next_run
    }

    /// Convert to executable Job
    pub fn to_job(&self) -> Job {
        Job::scheduled(
            self.job_type.clone(),
            self.priority,
            self.cron_expression.clone(),
            self.next_run,
        )
    }
}

/// Job scheduler that manages recurring scheduled jobs
pub struct JobScheduler {
    queue: Arc<tokio::sync::Mutex<JobQueue>>,
    scheduled_jobs: Arc<tokio::sync::RwLock<Vec<ScheduledJob>>>,
    running: Arc<tokio::sync::RwLock<bool>>,
    check_interval_seconds: u64,
}

impl JobScheduler {
    /// Create a new job scheduler
    pub fn new(queue: JobQueue, check_interval_seconds: u64) -> Self {
        Self {
            queue: Arc::new(tokio::sync::Mutex::new(queue)),
            scheduled_jobs: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            running: Arc::new(tokio::sync::RwLock::new(false)),
            check_interval_seconds,
        }
    }

    /// Add a scheduled job
    pub async fn add_scheduled_job(&self, job: ScheduledJob) -> Result<()> {
        let mut jobs = self.scheduled_jobs.write().await;
        jobs.push(job.clone());
        info!("Added scheduled job: {} ({})", job.name, job.cron_expression);
        Ok(())
    }

    /// Remove a scheduled job by ID
    pub async fn remove_scheduled_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self.scheduled_jobs.write().await;
        jobs.retain(|j| j.id != job_id);
        info!("Removed scheduled job: {}", job_id);
        Ok(())
    }

    /// Get all scheduled jobs
    pub async fn get_scheduled_jobs(&self) -> Vec<ScheduledJob> {
        let jobs = self.scheduled_jobs.read().await;
        jobs.clone()
    }

    /// Update a scheduled job
    pub async fn update_scheduled_job(&self, updated_job: ScheduledJob) -> Result<()> {
        let mut jobs = self.scheduled_jobs.write().await;
        if let Some(job) = jobs.iter_mut().find(|j| j.id == updated_job.id) {
            *job = updated_job;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Scheduled job not found"))
        }
    }

    /// Start the scheduler
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(anyhow::anyhow!("Scheduler is already running"));
        }
        *running = true;
        drop(running);

        info!("Job scheduler started (checking every {} seconds)", self.check_interval_seconds);

        let queue = Arc::clone(&self.queue);
        let scheduled_jobs = Arc::clone(&self.scheduled_jobs);
        let running = Arc::clone(&self.running);
        let check_interval = self.check_interval_seconds;

        tokio::spawn(async move {
            let mut tick_interval = interval(Duration::from_secs(check_interval));

            while *running.read().await {
                tick_interval.tick().await;

                debug!("Checking for due scheduled jobs...");

                let mut jobs = scheduled_jobs.write().await;
                let mut queue_guard = queue.lock().await;

                for job in jobs.iter_mut() {
                    if job.is_due() {
                        info!("Scheduled job '{}' is due, enqueuing...", job.name);

                        // Create executable job
                        let executable_job = job.to_job();

                        // Enqueue the job
                        match queue_guard.enqueue(executable_job).await {
                            Ok(_) => {
                                // Mark as executed and calculate next run
                                if let Err(e) = job.mark_executed() {
                                    error!("Failed to update scheduled job '{}': {}", job.name, e);
                                } else {
                                    info!("Scheduled job '{}' enqueued. Next run: {}", job.name, job.next_run);
                                }
                            }
                            Err(e) => {
                                error!("Failed to enqueue scheduled job '{}': {}", job.name, e);
                            }
                        }
                    }
                }
            }

            info!("Job scheduler stopped");
        });

        Ok(())
    }

    /// Stop the scheduler
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
        info!("Job scheduler stopping...");
    }

    /// Check if scheduler is running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

/// Predefined cron expressions for common schedules
/// Note: The `cron` crate expects 6-part expressions (seconds minutes hours day-of-month month day-of-week)
pub mod schedules {
    /// Every minute
    pub const EVERY_MINUTE: &str = "0 * * * * *";

    /// Every 5 minutes
    pub const EVERY_5_MINUTES: &str = "0 */5 * * * *";

    /// Every 15 minutes
    pub const EVERY_15_MINUTES: &str = "0 */15 * * * *";

    /// Every 30 minutes
    pub const EVERY_30_MINUTES: &str = "0 */30 * * * *";

    /// Every hour
    pub const HOURLY: &str = "0 0 * * * *";

    /// Daily at midnight UTC
    pub const DAILY: &str = "0 0 0 * * *";

    /// Daily at 2 AM UTC
    pub const DAILY_2AM: &str = "0 0 2 * * *";

    /// Weekly on Sunday at midnight UTC
    pub const WEEKLY: &str = "0 0 0 * * 0";

    /// Monthly on the 1st at midnight UTC
    pub const MONTHLY: &str = "0 0 0 1 * *";

    /// Business hours: Monday-Friday, 9 AM - 5 PM UTC
    pub const BUSINESS_HOURS: &str = "0 0 9-17 * * 1-5";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_expression_validation() {
        // Valid expressions
        assert!(ScheduledJob::new(
            "test".to_string(),
            schedules::DAILY.to_string(),
            JobType::DbCleanup { older_than_days: 30 },
            JobPriority::Low,
        ).is_ok());

        // Invalid expression
        assert!(ScheduledJob::new(
            "test".to_string(),
            "invalid cron".to_string(),
            JobType::DbCleanup { older_than_days: 30 },
            JobPriority::Low,
        ).is_err());
    }

    #[test]
    fn test_is_due() {
        let mut job = ScheduledJob::new(
            "test".to_string(),
            schedules::DAILY.to_string(),
            JobType::DbCleanup { older_than_days: 30 },
            JobPriority::Low,
        ).unwrap();

        // Job in the future should not be due
        assert!(!job.is_due());

        // Simulate past due
        job.next_run = Utc::now() - chrono::Duration::hours(1);
        assert!(job.is_due());

        // Inactive job should not be due
        job.is_active = false;
        assert!(!job.is_due());
    }

    #[tokio::test]
    async fn test_scheduler_lifecycle() {
        // Skip if Redis not available
        let queue = JobQueue::new("redis://localhost:6379").await;
        if queue.is_err() {
            println!("Skipping test: Redis not available");
            return;
        }

        let scheduler = JobScheduler::new(queue.unwrap(), 1);

        // Start scheduler
        assert!(!scheduler.is_running().await);
        scheduler.start().await.unwrap();
        assert!(scheduler.is_running().await);

        // Stop scheduler
        scheduler.stop().await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!scheduler.is_running().await);
    }
}
