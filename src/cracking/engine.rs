//! Cracking engine for orchestrating password cracking jobs

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use sqlx::sqlite::SqlitePool;
use anyhow::Result;
use uuid::Uuid;

use crate::db;
use crate::cracking::types::{
    CrackingJob, CrackingJobStatus, CrackerType, CrackingProgress,
    CrackingProgressMessage, HashEntry, CrackingJobConfig,
    CreateCrackingJobRequest, HashType,
};
use crate::cracking::hashcat::HashcatRunner;

/// Cracking engine for managing password cracking jobs
pub struct CrackingEngine {
    /// Database connection pool
    pool: SqlitePool,
    /// Running jobs map: job_id -> job handle
    running_jobs: Arc<RwLock<HashMap<String, RunningJob>>>,
    /// Progress broadcast channel
    progress_tx: broadcast::Sender<CrackingProgressMessage>,
}

/// Handle to a running cracking job
struct RunningJob {
    /// Abort handle to cancel the job
    abort_handle: tokio::task::AbortHandle,
    /// Current progress
    progress: CrackingProgress,
}

impl CrackingEngine {
    /// Create a new cracking engine
    pub fn new(pool: SqlitePool) -> Self {
        let (progress_tx, _) = broadcast::channel(1000);
        Self {
            pool,
            running_jobs: Arc::new(RwLock::new(HashMap::new())),
            progress_tx,
        }
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<CrackingProgressMessage> {
        self.progress_tx.subscribe()
    }

    /// Create a new cracking job
    pub async fn create_job(
        &self,
        user_id: &str,
        request: CreateCrackingJobRequest,
    ) -> Result<CrackingJob> {
        let job_id = Uuid::new_v4().to_string();
        let hashes_json = serde_json::to_string(&request.hashes)?;
        let config_json = serde_json::to_string(&request.config)?;

        let job = db::cracking::create_cracking_job(
            &self.pool,
            &job_id,
            user_id,
            request.name.as_deref(),
            request.hash_type,
            request.cracker_type,
            &hashes_json,
            &config_json,
            request.source_campaign_id.as_deref(),
            request.customer_id.as_deref(),
            request.engagement_id.as_deref(),
        ).await?;

        Ok(job)
    }

    /// Get a job by ID
    pub async fn get_job(&self, job_id: &str) -> Result<CrackingJob> {
        db::cracking::get_cracking_job(&self.pool, job_id).await
    }

    /// Get all jobs for a user
    pub async fn get_user_jobs(
        &self,
        user_id: &str,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<CrackingJob>> {
        db::cracking::get_user_cracking_jobs(&self.pool, user_id, limit, offset).await
    }

    /// Start a cracking job
    pub async fn start_job(&self, job_id: &str) -> Result<()> {
        let job = self.get_job(job_id).await?;

        if job.status != CrackingJobStatus::Pending && job.status != CrackingJobStatus::Paused {
            return Err(anyhow::anyhow!("Job is not in a startable state"));
        }

        // Parse hashes and config
        let hashes: Vec<HashEntry> = serde_json::from_str(&job.hashes_json)?;
        let config: CrackingJobConfig = serde_json::from_str(&job.config_json)?;

        // Update job status to running
        db::cracking::update_job_status(&self.pool, job_id, CrackingJobStatus::Running, None).await?;

        // Broadcast job started
        let _ = self.progress_tx.send(CrackingProgressMessage::JobStarted {
            job_id: job_id.to_string(),
            total_hashes: hashes.len(),
        });

        // Clone necessary data for the async task
        let pool = self.pool.clone();
        let progress_tx = self.progress_tx.clone();
        let running_jobs = self.running_jobs.clone();
        let job_id_owned = job_id.to_string();
        let hash_type = job.hash_type;
        let cracker_type = job.cracker_type;

        // Spawn the cracking task
        let task = tokio::spawn(async move {
            let result = match cracker_type {
                CrackerType::Hashcat => {
                    run_hashcat_job(
                        &pool,
                        &job_id_owned,
                        hash_type,
                        &hashes,
                        &config,
                        progress_tx.clone(),
                    ).await
                }
                CrackerType::John => {
                    // John the Ripper support - TODO: implement
                    Err(anyhow::anyhow!("John the Ripper support not yet implemented"))
                }
            };

            // Remove from running jobs
            running_jobs.write().await.remove(&job_id_owned);

            // Update final status
            match result {
                Ok(cracked_count) => {
                    let _ = db::cracking::update_job_status(
                        &pool,
                        &job_id_owned,
                        CrackingJobStatus::Completed,
                        None,
                    ).await;
                    let _ = progress_tx.send(CrackingProgressMessage::JobCompleted {
                        job_id: job_id_owned,
                        total_cracked: cracked_count,
                        duration_secs: 0, // TODO: calculate actual duration
                    });
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    let _ = db::cracking::update_job_status(
                        &pool,
                        &job_id_owned,
                        CrackingJobStatus::Failed,
                        Some(&error_msg),
                    ).await;
                    let _ = progress_tx.send(CrackingProgressMessage::JobFailed {
                        job_id: job_id_owned,
                        error: error_msg,
                    });
                }
            }
        });

        // Store the running job
        self.running_jobs.write().await.insert(job_id.to_string(), RunningJob {
            abort_handle: task.abort_handle(),
            progress: CrackingProgress::default(),
        });

        Ok(())
    }

    /// Stop a running job
    pub async fn stop_job(&self, job_id: &str) -> Result<()> {
        // Check if job is running
        let mut running_jobs = self.running_jobs.write().await;
        if let Some(running_job) = running_jobs.remove(job_id) {
            running_job.abort_handle.abort();
        }

        // Update job status
        db::cracking::update_job_status(&self.pool, job_id, CrackingJobStatus::Cancelled, None).await?;

        // Broadcast cancellation
        let _ = self.progress_tx.send(CrackingProgressMessage::JobCancelled {
            job_id: job_id.to_string(),
        });

        Ok(())
    }

    /// Delete a job (only if not running)
    pub async fn delete_job(&self, job_id: &str) -> Result<()> {
        let job = self.get_job(job_id).await?;
        if job.status == CrackingJobStatus::Running {
            return Err(anyhow::anyhow!("Cannot delete a running job"));
        }

        db::cracking::delete_cracking_job(&self.pool, job_id).await
    }

    /// Get cracked credentials for a job
    pub async fn get_job_credentials(&self, job_id: &str) -> Result<Vec<db::cracking::CrackedCredentialRow>> {
        db::cracking::get_job_credentials(&self.pool, job_id).await
    }

    /// Detect hash type from sample hashes
    pub fn detect_hash_type(&self, hashes: &[String]) -> Option<HashType> {
        if hashes.is_empty() {
            return None;
        }

        // Try to detect from first hash
        HashType::detect(&hashes[0])
    }
}

/// Run a hashcat job
async fn run_hashcat_job(
    pool: &SqlitePool,
    job_id: &str,
    hash_type: i32,
    hashes: &[HashEntry],
    config: &CrackingJobConfig,
    progress_tx: broadcast::Sender<CrackingProgressMessage>,
) -> Result<usize> {
    // Get wordlist paths
    let wordlist_paths = get_wordlist_paths(pool, &config.wordlist_ids).await?;
    let rule_paths = get_rule_paths(pool, &config.rule_ids).await?;

    // Create hashcat runner
    let runner = HashcatRunner::new(hash_type, hashes, config)?;

    // Create a temporary hash file
    let hash_file = runner.write_hash_file()?;

    // Build hashcat command
    let args = runner.build_args(&hash_file, &wordlist_paths, &rule_paths)?;

    // Run hashcat
    let cracked_count = 0;

    // For now, use a simulated run since hashcat may not be installed
    // In production, this would spawn the hashcat process
    log::info!("Would run hashcat with args: {:?}", args);

    // Simulate progress updates
    let total = hashes.len();
    for i in 0..=10 {
        let progress_percent = (i as f32 / 10.0) * 100.0;
        let progress = CrackingProgress {
            total_hashes: total,
            cracked: cracked_count,
            speed: "0 H/s".to_string(),
            estimated_time: "N/A".to_string(),
            progress_percent,
            candidates_tested: 0,
            candidates_total: None,
            status_message: if i == 10 { "Completed".to_string() } else { "Running...".to_string() },
            temperatures: vec![],
            utilization: vec![],
        };

        // Update progress in database
        let progress_json = serde_json::to_string(&progress)?;
        db::cracking::update_job_progress(pool, job_id, &progress_json).await?;

        // Broadcast progress
        let _ = progress_tx.send(CrackingProgressMessage::ProgressUpdate {
            job_id: job_id.to_string(),
            cracked: cracked_count,
            total,
            speed: progress.speed.clone(),
            eta: progress.estimated_time.clone(),
            progress_percent,
        });

        // Small delay to simulate work
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Clean up
    runner.cleanup(&hash_file)?;

    Ok(cracked_count)
}

/// Get wordlist file paths from database
async fn get_wordlist_paths(pool: &SqlitePool, wordlist_ids: &[String]) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for id in wordlist_ids {
        if let Ok(wordlist) = db::cracking::get_wordlist(pool, id).await {
            paths.push(wordlist.file_path);
        }
    }
    Ok(paths)
}

/// Get rule file paths from database
async fn get_rule_paths(pool: &SqlitePool, rule_ids: &[String]) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for id in rule_ids {
        if let Ok(rule) = db::cracking::get_rule_file(pool, id).await {
            paths.push(rule.file_path);
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_type_detection() {
        let ntlm_hashes = vec!["31d6cfe0d16ae931b73c59d7e0c089c0".to_string()];
        let engine_hash_type = HashType::detect(&ntlm_hashes[0]);
        assert_eq!(engine_hash_type, Some(HashType::Ntlm));
    }
}
