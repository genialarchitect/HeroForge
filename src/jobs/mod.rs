//! Background job processing system
//!
//! Provides async job queue with:
//! - Job scheduling and execution
//! - Retry logic with exponential backoff
//! - Job progress tracking
//! - Priority queues
//! - Distributed job processing

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

pub mod executor;
pub mod queue;
pub mod scheduler;
pub mod types;

/// Job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Retrying,
    Cancelled,
}

/// Job priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum JobPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Background job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub job_type: String,
    pub payload: serde_json::Value,
    pub status: JobStatus,
    pub priority: JobPriority,
    pub max_retries: u32,
    pub retry_count: u32,
    pub retry_delay_seconds: u64,
    pub timeout_seconds: Option<u64>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub progress: Option<f32>,
    pub result: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Job {
    /// Create a new job
    pub fn new(job_type: impl Into<String>, payload: serde_json::Value) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            job_type: job_type.into(),
            payload,
            status: JobStatus::Pending,
            priority: JobPriority::Normal,
            max_retries: 3,
            retry_count: 0,
            retry_delay_seconds: 60,
            timeout_seconds: Some(3600), // 1 hour default
            scheduled_at: None,
            started_at: None,
            completed_at: None,
            error: None,
            progress: None,
            result: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set job priority
    pub fn with_priority(mut self, priority: JobPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set max retries
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set retry delay
    pub fn with_retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay_seconds = delay.as_secs();
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_seconds = Some(timeout.as_secs());
        self
    }

    /// Schedule job for future execution
    pub fn schedule_at(mut self, scheduled_at: DateTime<Utc>) -> Self {
        self.scheduled_at = Some(scheduled_at);
        self
    }

    /// Mark job as started
    pub fn mark_started(&mut self) {
        self.status = JobStatus::Running;
        self.started_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Mark job as completed
    pub fn mark_completed(&mut self, result: Option<serde_json::Value>) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.result = result;
        self.progress = Some(100.0);
        self.updated_at = Utc::now();
    }

    /// Mark job as failed
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = JobStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error.into());
        self.updated_at = Utc::now();
    }

    /// Update job progress
    pub fn update_progress(&mut self, progress: f32) {
        self.progress = Some(progress.clamp(0.0, 100.0));
        self.updated_at = Utc::now();
    }

    /// Should retry?
    pub fn should_retry(&self) -> bool {
        self.status == JobStatus::Failed && self.retry_count < self.max_retries
    }

    /// Calculate next retry delay with exponential backoff
    pub fn next_retry_delay(&self) -> Duration {
        let base_delay = self.retry_delay_seconds;
        let backoff_multiplier = 2_u64.pow(self.retry_count);
        let delay_secs = base_delay * backoff_multiplier;
        Duration::from_secs(delay_secs)
    }
}

/// Job type definitions
pub mod job_types {
    pub const SCAN_EXECUTION: &str = "scan_execution";
    pub const VULNERABILITY_SCAN: &str = "vulnerability_scan";
    pub const REPORT_GENERATION: &str = "report_generation";
    pub const COMPLIANCE_CHECK: &str = "compliance_check";
    pub const THREAT_INTEL_UPDATE: &str = "threat_intel_update";
    pub const ASSET_DISCOVERY: &str = "asset_discovery";
    pub const NOTIFICATION_SEND: &str = "notification_send";
    pub const DATA_EXPORT: &str = "data_export";
    pub const BACKUP: &str = "backup";
    pub const CLEANUP: &str = "cleanup";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_creation() {
        let payload = serde_json::json!({"target": "192.168.1.1"});
        let job = Job::new("scan", payload);

        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.priority, JobPriority::Normal);
        assert_eq!(job.retry_count, 0);
    }

    #[test]
    fn test_retry_logic() {
        let mut job = Job::new("test", serde_json::json!({}));
        job.mark_failed("Test error");

        assert!(job.should_retry());

        job.retry_count = 3;
        assert!(!job.should_retry());
    }

    #[test]
    fn test_exponential_backoff() {
        let job = Job::new("test", serde_json::json!({}))
            .with_retry_delay(Duration::from_secs(60));

        assert_eq!(job.next_retry_delay(), Duration::from_secs(60)); // 60 * 2^0

        let mut job2 = job.clone();
        job2.retry_count = 1;
        assert_eq!(job2.next_retry_delay(), Duration::from_secs(120)); // 60 * 2^1

        let mut job3 = job.clone();
        job3.retry_count = 2;
        assert_eq!(job3.next_retry_delay(), Duration::from_secs(240)); // 60 * 2^2
    }
}
