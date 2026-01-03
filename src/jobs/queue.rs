//! Redis-backed job queue implementation

use super::types::{Job, JobPriority, JobStatus, JobStats};
use anyhow::{Result, Context};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde_json;
use log::{debug, error, info};

/// Redis-backed job queue
pub struct JobQueue {
    redis: ConnectionManager,
    queue_prefix: String,
}

impl JobQueue {
    /// Create a new job queue with Redis connection
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .context("Failed to create Redis client")?;

        let redis = ConnectionManager::new(client).await
            .context("Failed to connect to Redis")?;

        Ok(Self {
            redis,
            queue_prefix: "heroforge:jobs".to_string(),
        })
    }

    /// Enqueue a new job
    pub async fn enqueue(&mut self, job: Job) -> Result<()> {
        let job_json = serde_json::to_string(&job)?;

        // Store job data
        let job_key = format!("{}:job:{}", self.queue_prefix, job.id);
        self.redis.set::<_, _, ()>(&job_key, &job_json).await?;

        // Add to priority queue (sorted set by priority and created_at)
        let queue_key = format!("{}:queue", self.queue_prefix);
        let score = self.calculate_priority_score(&job);
        self.redis.zadd::<_, _, _, ()>(&queue_key, &job.id, score).await?;

        // Track job status
        let status_key = format!("{}:status:{:?}", self.queue_prefix, job.status);
        self.redis.sadd::<_, _, ()>(&status_key, &job.id).await?;

        debug!("Enqueued job {} with priority {:?}", job.id, job.priority);
        Ok(())
    }

    /// Dequeue next job (highest priority)
    pub async fn dequeue(&mut self) -> Result<Option<Job>> {
        let queue_key = format!("{}:queue", self.queue_prefix);

        // Get highest priority job (highest score)
        let result: Option<(String, f64)> = self.redis
            .zpopmax::<_, Vec<(String, f64)>>(&queue_key, 1)
            .await?
            .into_iter()
            .next();

        if let Some((job_id, _score)) = result {
            let job_key = format!("{}:job:{}", self.queue_prefix, job_id);
            let job_json: Option<String> = self.redis.get(&job_key).await?;

            if let Some(json) = job_json {
                let mut job: Job = serde_json::from_str(&json)?;

                // Update status
                job.start();
                self.update_job(&job).await?;

                debug!("Dequeued job {}", job.id);
                return Ok(Some(job));
            }
        }

        Ok(None)
    }

    /// Update job status and data
    pub async fn update_job(&mut self, job: &Job) -> Result<()> {
        let job_json = serde_json::to_string(job)?;
        let job_key = format!("{}:job:{}", self.queue_prefix, job.id);

        // Update job data
        self.redis.set::<_, _, ()>(&job_key, &job_json).await?;

        // Update status tracking
        for status in &[JobStatus::Pending, JobStatus::Running, JobStatus::Completed, JobStatus::Failed, JobStatus::Retrying] {
            let status_key = format!("{}:status:{:?}", self.queue_prefix, status);
            if *status == job.status {
                self.redis.sadd::<_, _, ()>(&status_key, &job.id).await?;
            } else {
                self.redis.srem::<_, _, ()>(&status_key, &job.id).await?;
            }
        }

        Ok(())
    }

    /// Get job by ID
    pub async fn get_job(&mut self, job_id: &str) -> Result<Option<Job>> {
        let job_key = format!("{}:job:{}", self.queue_prefix, job_id);
        let job_json: Option<String> = self.redis.get(&job_key).await?;

        if let Some(json) = job_json {
            let job: Job = serde_json::from_str(&json)?;
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    /// Delete job from queue
    pub async fn delete_job(&mut self, job_id: &str) -> Result<()> {
        let job_key = format!("{}:job:{}", self.queue_prefix, job_id);
        let queue_key = format!("{}:queue", self.queue_prefix);

        // Get job to determine status
        if let Some(job) = self.get_job(job_id).await? {
            let status_key = format!("{}:status:{:?}", self.queue_prefix, job.status);
            self.redis.srem::<_, _, ()>(&status_key, job_id).await?;
        }

        // Remove from queue and delete job data
        self.redis.zrem::<_, _, ()>(&queue_key, job_id).await?;
        self.redis.del::<_, ()>(&job_key).await?;

        debug!("Deleted job {}", job_id);
        Ok(())
    }

    /// Requeue a failed job for retry
    pub async fn requeue(&mut self, mut job: Job) -> Result<()> {
        if !job.can_retry() {
            return Err(anyhow::anyhow!("Job {} has exceeded max retries", job.id));
        }

        job.retry();

        // Re-add to queue
        let queue_key = format!("{}:queue", self.queue_prefix);
        let score = self.calculate_priority_score(&job);
        self.redis.zadd::<_, _, _, ()>(&queue_key, &job.id, score).await?;

        self.update_job(&job).await?;

        info!("Requeued job {} for retry (attempt {}/{})", job.id, job.retry_count, job.max_retries);
        Ok(())
    }

    /// Get jobs by status
    pub async fn get_jobs_by_status(&mut self, status: JobStatus) -> Result<Vec<Job>> {
        let status_key = format!("{}:status:{:?}", self.queue_prefix, status);
        let job_ids: Vec<String> = self.redis.smembers(&status_key).await?;

        let mut jobs = Vec::new();
        for job_id in job_ids {
            if let Some(job) = self.get_job(&job_id).await? {
                jobs.push(job);
            }
        }

        Ok(jobs)
    }

    /// Get queue statistics
    pub async fn get_stats(&mut self) -> Result<JobStats> {
        let pending = self.count_by_status(JobStatus::Pending).await?;
        let running = self.count_by_status(JobStatus::Running).await?;
        let completed = self.count_by_status(JobStatus::Completed).await?;
        let failed = self.count_by_status(JobStatus::Failed).await?;

        let total = pending + running + completed + failed;

        // Calculate average duration for completed jobs
        let completed_jobs = self.get_jobs_by_status(JobStatus::Completed).await?;
        let avg_duration = if !completed_jobs.is_empty() {
            let total_duration: f64 = completed_jobs.iter()
                .filter_map(|j| {
                    j.started_at.and_then(|start| {
                        j.completed_at.map(|end| {
                            (end - start).num_seconds() as f64
                        })
                    })
                })
                .sum();
            total_duration / completed_jobs.len() as f64
        } else {
            0.0
        };

        Ok(JobStats {
            total_jobs: total,
            pending_jobs: pending,
            running_jobs: running,
            completed_jobs: completed,
            failed_jobs: failed,
            average_duration_seconds: avg_duration,
        })
    }

    /// Count jobs by status
    async fn count_by_status(&mut self, status: JobStatus) -> Result<u64> {
        let status_key = format!("{}:status:{:?}", self.queue_prefix, status);
        let count: u64 = self.redis.scard(&status_key).await?;
        Ok(count)
    }

    /// Calculate priority score for sorting in Redis sorted set
    /// Higher score = higher priority
    fn calculate_priority_score(&self, job: &Job) -> f64 {
        // Priority weight (0-3) * 1,000,000 + timestamp
        // This ensures higher priority jobs come first, with FIFO for same priority
        let priority_weight = (job.priority as u32) as f64 * 1_000_000.0;
        let timestamp = job.created_at.timestamp() as f64;
        priority_weight + timestamp
    }

    /// Clean up old completed/failed jobs
    pub async fn cleanup_old_jobs(&mut self, older_than_days: u32) -> Result<u64> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(older_than_days as i64);
        let mut deleted_count = 0;

        for status in &[JobStatus::Completed, JobStatus::Failed] {
            let jobs = self.get_jobs_by_status(*status).await?;

            for job in jobs {
                if job.completed_at.map(|t| t < cutoff).unwrap_or(false) {
                    self.delete_job(&job.id).await?;
                    deleted_count += 1;
                }
            }
        }

        info!("Cleaned up {} old jobs", deleted_count);
        Ok(deleted_count)
    }

    /// Get pending jobs count
    pub async fn pending_count(&mut self) -> Result<u64> {
        let queue_key = format!("{}:queue", self.queue_prefix);
        let count: u64 = self.redis.zcard(&queue_key).await?;
        Ok(count)
    }

    /// Clear all jobs (use with caution!)
    pub async fn clear_all(&mut self) -> Result<()> {
        let pattern = format!("{}:*", self.queue_prefix);
        let keys: Vec<String> = self.redis.keys(&pattern).await?;

        if !keys.is_empty() {
            self.redis.del::<_, ()>(keys).await?;
        }

        info!("Cleared all jobs from queue");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::types::JobType;

    #[tokio::test]
    async fn test_job_queue_basic_operations() {
        // This test requires Redis running on localhost:6379
        // Skip if Redis is not available
        let queue = JobQueue::new("redis://localhost:6379").await;
        if queue.is_err() {
            println!("Skipping test: Redis not available");
            return;
        }

        let mut queue = queue.unwrap();
        queue.clear_all().await.unwrap();

        // Create and enqueue a job
        let job = Job::new(
            JobType::Scan {
                scan_id: "scan-123".to_string(),
                user_id: "user-456".to_string(),
            },
            JobPriority::Normal,
        );

        let job_id = job.id.clone();
        queue.enqueue(job).await.unwrap();

        // Verify job was enqueued
        assert_eq!(queue.pending_count().await.unwrap(), 1);

        // Dequeue and verify
        let dequeued = queue.dequeue().await.unwrap();
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().id, job_id);
    }
}
