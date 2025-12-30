//! Job types and definitions for the job queue system

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum JobPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Retrying,
}

/// Job types available in HeroForge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum JobType {
    /// Network scan job
    Scan {
        scan_id: String,
        user_id: String,
    },
    /// Report generation job
    Report {
        scan_id: String,
        format: String,
        user_id: String,
    },
    /// Vulnerability rescan job
    VulnRescan {
        vuln_ids: Vec<String>,
        user_id: String,
    },
    /// Database cleanup job
    DbCleanup {
        older_than_days: u32,
    },
    /// Email notification job
    EmailNotification {
        to: String,
        subject: String,
        body: String,
    },
    /// Webhook delivery job
    WebhookDelivery {
        webhook_id: String,
        event_type: String,
        payload: String,
    },
    /// Scheduled scan execution
    ScheduledScan {
        scheduled_scan_id: String,
        user_id: String,
    },
    /// SIEM export job
    SiemExport {
        scan_id: String,
        integration_id: String,
    },
    /// Asset discovery job
    AssetDiscovery {
        user_id: String,
        network_ranges: Vec<String>,
    },
    /// Compliance report generation
    ComplianceReport {
        scan_id: String,
        framework: String,
        user_id: String,
    },
    /// Backup job
    Backup {
        backup_type: String,
        destination: String,
    },
}

/// Job metadata and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Unique job identifier
    pub id: String,

    /// Job type and data
    pub job_type: JobType,

    /// Job priority
    pub priority: JobPriority,

    /// Current job status
    pub status: JobStatus,

    /// Number of retry attempts made
    pub retry_count: u32,

    /// Maximum number of retries allowed
    pub max_retries: u32,

    /// Job timeout in seconds
    pub timeout_seconds: u64,

    /// When the job was created
    pub created_at: DateTime<Utc>,

    /// When the job was started (if running)
    pub started_at: Option<DateTime<Utc>>,

    /// When the job was completed
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message if failed
    pub error: Option<String>,

    /// Job result data (JSON)
    pub result: Option<String>,

    /// Schedule for recurring jobs (cron expression)
    pub schedule: Option<String>,

    /// Next scheduled run time
    pub next_run_at: Option<DateTime<Utc>>,
}

impl Job {
    /// Create a new job
    pub fn new(job_type: JobType, priority: JobPriority) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            job_type,
            priority,
            status: JobStatus::Pending,
            retry_count: 0,
            max_retries: 3,
            timeout_seconds: 3600, // 1 hour default
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error: None,
            result: None,
            schedule: None,
            next_run_at: None,
        }
    }

    /// Create a scheduled job
    pub fn scheduled(job_type: JobType, priority: JobPriority, cron_expression: String, next_run: DateTime<Utc>) -> Self {
        let mut job = Self::new(job_type, priority);
        job.schedule = Some(cron_expression);
        job.next_run_at = Some(next_run);
        job
    }

    /// Mark job as started
    pub fn start(&mut self) {
        self.status = JobStatus::Running;
        self.started_at = Some(Utc::now());
    }

    /// Mark job as completed
    pub fn complete(&mut self, result: Option<String>) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.result = result;
    }

    /// Mark job as failed
    pub fn fail(&mut self, error: String) {
        self.status = JobStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
    }

    /// Check if job can be retried
    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    /// Increment retry count
    pub fn retry(&mut self) {
        self.retry_count += 1;
        self.status = JobStatus::Retrying;
        self.started_at = None;
    }
}

/// Job execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobResult {
    Success(String),
    Failure(String),
}

/// Job statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStats {
    pub total_jobs: u64,
    pub pending_jobs: u64,
    pub running_jobs: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub average_duration_seconds: f64,
}
