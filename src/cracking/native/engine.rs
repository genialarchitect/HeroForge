//! Native password cracking engine
//!
//! Main orchestration for native password cracking operations.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock};
use rayon::prelude::*;
use log::info;

use super::hashes::HashType;
use super::attacks::{Attack, AttackExecutor, DictionaryAttack, BruteForceAttack, RuleBasedAttack, MaskAttack};
use super::wordlists::{EmbeddedWordlists, WordlistManager};
use super::types::{CrackResult, CrackProgress, NativeCrackConfig, HashAlgorithm};

/// Native cracking job status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// A native cracking job
#[derive(Debug, Clone)]
pub struct NativeCrackJob {
    /// Job ID
    pub id: String,
    /// Target hashes
    pub hashes: Vec<String>,
    /// Hash type
    pub hash_type: HashType,
    /// Attack mode
    pub attack_mode: AttackMode,
    /// Configuration
    pub config: NativeCrackConfig,
    /// Status
    pub status: JobStatus,
    /// Results
    pub results: Vec<CrackResult>,
    /// Error message if failed
    pub error: Option<String>,
    /// Start time
    pub started_at: Option<Instant>,
    /// End time
    pub ended_at: Option<Instant>,
}

/// Attack mode for native cracking
#[derive(Debug, Clone)]
pub enum AttackMode {
    /// Dictionary attack with wordlist
    Dictionary {
        wordlist: Vec<String>,
    },
    /// Dictionary from embedded wordlist
    EmbeddedWordlist {
        name: String,
    },
    /// Brute-force attack
    BruteForce {
        min_length: usize,
        max_length: usize,
        charset: Option<String>,
    },
    /// Mask attack
    Mask {
        mask: String,
        custom_charsets: Option<[String; 4]>,
    },
    /// Rule-based attack
    RuleBased {
        wordlist: Vec<String>,
        rules: Vec<String>,
    },
    /// Quick attack (embedded wordlist + common rules)
    Quick,
    /// Comprehensive attack (tries multiple modes)
    Comprehensive,
}

impl Default for AttackMode {
    fn default() -> Self {
        AttackMode::Quick
    }
}

/// Native password cracking engine
pub struct NativeCrackingEngine {
    /// Configuration
    config: NativeCrackConfig,
    /// Active jobs
    jobs: Arc<RwLock<std::collections::HashMap<String, NativeCrackJob>>>,
    /// Progress broadcast channel
    progress_tx: broadcast::Sender<(String, CrackProgress)>,
    /// Wordlist manager
    wordlist_manager: Option<WordlistManager>,
}

impl NativeCrackingEngine {
    /// Create a new native cracking engine
    pub fn new(config: NativeCrackConfig) -> Self {
        let (progress_tx, _) = broadcast::channel(1000);
        Self {
            config,
            jobs: Arc::new(RwLock::new(std::collections::HashMap::new())),
            progress_tx,
            wordlist_manager: None,
        }
    }

    /// Create with wordlist manager
    pub fn with_wordlist_manager(mut self, manager: WordlistManager) -> Self {
        self.wordlist_manager = Some(manager);
        self
    }

    /// Subscribe to progress updates
    pub fn subscribe(&self) -> broadcast::Receiver<(String, CrackProgress)> {
        self.progress_tx.subscribe()
    }

    /// Detect hash type from sample hashes
    pub fn detect_hash_type(&self, hashes: &[String]) -> Option<HashType> {
        if hashes.is_empty() {
            return None;
        }
        HashType::detect(&hashes[0])
    }

    /// Create a new cracking job
    pub async fn create_job(
        &self,
        hashes: Vec<String>,
        hash_type: HashType,
        attack_mode: AttackMode,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();

        let job = NativeCrackJob {
            id: id.clone(),
            hashes,
            hash_type,
            attack_mode,
            config: self.config.clone(),
            status: JobStatus::Pending,
            results: Vec::new(),
            error: None,
            started_at: None,
            ended_at: None,
        };

        self.jobs.write().await.insert(id.clone(), job);
        id
    }

    /// Start a cracking job
    pub async fn start_job(&self, job_id: &str) -> Result<(), String> {
        // Get job
        let mut job = {
            let jobs = self.jobs.read().await;
            jobs.get(job_id).cloned().ok_or("Job not found")?
        };

        if job.status != JobStatus::Pending {
            return Err("Job is not in pending state".to_string());
        }

        job.status = JobStatus::Running;
        job.started_at = Some(Instant::now());

        // Update job in storage
        self.jobs.write().await.insert(job_id.to_string(), job.clone());

        // Clone necessary data for async task
        let jobs = self.jobs.clone();
        let progress_tx = self.progress_tx.clone();
        let job_id = job_id.to_string();

        // Spawn cracking task
        tokio::spawn(async move {
            let result = run_cracking_job(&job, progress_tx.clone()).await;

            // Update job with results
            let mut jobs_guard = jobs.write().await;
            if let Some(stored_job) = jobs_guard.get_mut(&job_id) {
                match result {
                    Ok(results) => {
                        stored_job.results = results;
                        stored_job.status = JobStatus::Completed;
                    }
                    Err(e) => {
                        stored_job.error = Some(e);
                        stored_job.status = JobStatus::Failed;
                    }
                }
                stored_job.ended_at = Some(Instant::now());
            }
        });

        Ok(())
    }

    /// Cancel a running job
    pub async fn cancel_job(&self, job_id: &str) -> Result<(), String> {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            if job.status == JobStatus::Running {
                job.status = JobStatus::Cancelled;
                job.ended_at = Some(Instant::now());
                return Ok(());
            }
        }
        Err("Job not found or not running".to_string())
    }

    /// Get job status
    pub async fn get_job(&self, job_id: &str) -> Option<NativeCrackJob> {
        self.jobs.read().await.get(job_id).cloned()
    }

    /// Get all jobs
    pub async fn list_jobs(&self) -> Vec<NativeCrackJob> {
        self.jobs.read().await.values().cloned().collect()
    }

    /// Quick crack - try common passwords first
    pub async fn quick_crack(
        &self,
        hashes: Vec<String>,
        hash_type: HashType,
    ) -> Vec<CrackResult> {
        let algorithm = hash_type.algorithm();

        // Try embedded wordlists
        let words: Vec<String> = EmbeddedWordlists::top_1000()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        let attack = RuleBasedAttack::common_rules(DictionaryAttack::from_list(words));

        let executor = AttackExecutor::new(self.config.clone());
        executor.execute_sync(&attack, algorithm, &hashes)
    }

    /// Comprehensive crack - try multiple attack modes
    pub async fn comprehensive_crack(
        &self,
        hashes: Vec<String>,
        hash_type: HashType,
        max_duration: Duration,
    ) -> Vec<CrackResult> {
        let algorithm = hash_type.algorithm();
        let start = Instant::now();

        let mut results: Vec<CrackResult> = hashes
            .iter()
            .map(|h| CrackResult {
                hash: h.clone(),
                plaintext: None,
                duration: Duration::ZERO,
                candidates_tried: 0,
            })
            .collect();

        let executor = AttackExecutor::new(self.config.clone());

        // Phase 1: Quick dictionary attack
        info!("Phase 1: Quick dictionary attack");
        let words: Vec<String> = EmbeddedWordlists::top_100()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let attack = DictionaryAttack::from_list(words);
        let phase_results = executor.execute_sync(&attack, algorithm.clone(), &hashes);
        merge_results(&mut results, phase_results);

        if start.elapsed() > max_duration || all_cracked(&results) {
            return results;
        }

        // Phase 2: Rules-based attack with top 1000
        info!("Phase 2: Rules-based attack");
        let words: Vec<String> = EmbeddedWordlists::top_1000()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let attack = RuleBasedAttack::common_rules(DictionaryAttack::from_list(words));
        let uncracked = get_uncracked_hashes(&results);
        let phase_results = executor.execute_sync(&attack, algorithm.clone(), &uncracked);
        merge_results(&mut results, phase_results);

        if start.elapsed() > max_duration || all_cracked(&results) {
            return results;
        }

        // Phase 3: Numeric brute force (4-6 digits)
        info!("Phase 3: Numeric brute force");
        let attack = BruteForceAttack::digits(4, 6);
        let uncracked = get_uncracked_hashes(&results);
        let phase_results = executor.execute_sync(&attack, algorithm.clone(), &uncracked);
        merge_results(&mut results, phase_results);

        if start.elapsed() > max_duration || all_cracked(&results) {
            return results;
        }

        // Phase 4: Common mask patterns
        info!("Phase 4: Common mask patterns");
        let masks = vec![
            "?l?l?l?l?d?d",     // 4 letters + 2 digits
            "?u?l?l?l?l?d?d",   // Capital + 4 lower + 2 digits
            "?l?l?l?l?l?d",     // 5 letters + 1 digit
            "?l?l?l?l?l?l",     // 6 lowercase letters
        ];

        for mask in masks {
            if start.elapsed() > max_duration || all_cracked(&results) {
                break;
            }
            let attack = MaskAttack::new(mask);
            let uncracked = get_uncracked_hashes(&results);
            let phase_results = executor.execute_sync(&attack, algorithm.clone(), &uncracked);
            merge_results(&mut results, phase_results);
        }

        results
    }

    /// Single hash quick check
    pub fn verify_password(&self, password: &str, hash: &str, hash_type: HashType) -> bool {
        let algorithm = hash_type.algorithm();
        algorithm.verify(password.as_bytes(), hash)
    }

    /// Hash a password
    pub fn hash_password(&self, password: &str, hash_type: HashType) -> String {
        let algorithm = hash_type.algorithm();
        algorithm.hash(password.as_bytes())
    }
}

/// Run a cracking job
async fn run_cracking_job(
    job: &NativeCrackJob,
    progress_tx: broadcast::Sender<(String, CrackProgress)>,
) -> Result<Vec<CrackResult>, String> {
    let algorithm = job.hash_type.algorithm();

    // Create attack based on mode
    let attack: Box<dyn Attack> = match &job.attack_mode {
        AttackMode::Dictionary { wordlist } => {
            Box::new(DictionaryAttack::from_list(wordlist.clone()))
        }
        AttackMode::EmbeddedWordlist { name } => {
            let words = match name.as_str() {
                "top100" => EmbeddedWordlists::top_100()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
                "top1000" | _ => EmbeddedWordlists::top_1000()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
            };
            Box::new(DictionaryAttack::from_list(words))
        }
        AttackMode::BruteForce { min_length, max_length, charset } => {
            if let Some(cs) = charset {
                let cs = super::types::Charset::new("custom", cs);
                Box::new(BruteForceAttack::with_charset(cs, *min_length, *max_length))
            } else {
                Box::new(BruteForceAttack::new(*min_length, *max_length))
            }
        }
        AttackMode::Mask { mask, custom_charsets } => {
            if let Some(cs) = custom_charsets {
                Box::new(MaskAttack::with_custom_charsets(
                    mask, &cs[0], &cs[1], &cs[2], &cs[3],
                ))
            } else {
                Box::new(MaskAttack::new(mask))
            }
        }
        AttackMode::RuleBased { wordlist, rules: _ } => {
            // Parse rules (simplified)
            let dict = DictionaryAttack::from_list(wordlist.clone());
            Box::new(RuleBasedAttack::common_rules(dict))
        }
        AttackMode::Quick => {
            let words: Vec<String> = EmbeddedWordlists::top_1000()
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            Box::new(RuleBasedAttack::common_rules(DictionaryAttack::from_list(words)))
        }
        AttackMode::Comprehensive => {
            // For comprehensive, we run multiple phases
            // This is handled specially
            let words: Vec<String> = EmbeddedWordlists::top_1000()
                .into_iter()
                .map(|s| s.to_string())
                .collect();
            Box::new(RuleBasedAttack::aggressive_rules(DictionaryAttack::from_list(words)))
        }
    };

    // Create progress channel
    let (tx, mut rx) = mpsc::channel(100);

    // Forward progress to broadcast
    let job_id = job.id.clone();
    let progress_tx_clone = progress_tx.clone();
    tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            let _ = progress_tx_clone.send((job_id.clone(), progress));
        }
    });

    // Execute attack
    let executor = AttackExecutor::new(job.config.clone())
        .with_progress_channel(tx);

    Ok(executor.execute(&*attack, algorithm, &job.hashes).await)
}

/// Merge new results into existing results
fn merge_results(results: &mut Vec<CrackResult>, new_results: Vec<CrackResult>) {
    for new_result in new_results {
        if new_result.plaintext.is_some() {
            if let Some(existing) = results.iter_mut().find(|r| r.hash == new_result.hash) {
                if existing.plaintext.is_none() {
                    *existing = new_result;
                }
            }
        }
    }
}

/// Check if all hashes are cracked
fn all_cracked(results: &[CrackResult]) -> bool {
    results.iter().all(|r| r.plaintext.is_some())
}

/// Get uncracked hashes
fn get_uncracked_hashes(results: &[CrackResult]) -> Vec<String> {
    results
        .iter()
        .filter(|r| r.plaintext.is_none())
        .map(|r| r.hash.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_hash_type() {
        let engine = NativeCrackingEngine::new(NativeCrackConfig::default());

        let hashes = vec!["5d41402abc4b2a76b9719d911017c592".to_string()];
        // This could be MD5 or NTLM (both 32 hex chars)
        // Our detector defaults to NTLM for 32 hex chars
        let detected = engine.detect_hash_type(&hashes);
        assert!(detected.is_some());
    }

    #[tokio::test]
    async fn test_quick_crack() {
        let engine = NativeCrackingEngine::new(NativeCrackConfig {
            batch_size: 1000,
            max_candidates: 100000,
            ..Default::default()
        });

        // NTLM hash of "password"
        let hashes = vec!["8846f7eaee8fb117ad06bdd830b7586c".to_string()];
        let results = engine.quick_crack(hashes, HashType::Ntlm).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plaintext, Some("password".to_string()));
    }

    #[test]
    fn test_verify_password() {
        let engine = NativeCrackingEngine::new(NativeCrackConfig::default());

        // MD5
        assert!(engine.verify_password(
            "hello",
            "5d41402abc4b2a76b9719d911017c592",
            HashType::Md5
        ));

        // NTLM
        assert!(engine.verify_password(
            "password",
            "8846f7eaee8fb117ad06bdd830b7586c",
            HashType::Ntlm
        ));
    }

    #[test]
    fn test_hash_password() {
        let engine = NativeCrackingEngine::new(NativeCrackConfig::default());

        let hash = engine.hash_password("hello", HashType::Md5);
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");

        let hash = engine.hash_password("password", HashType::Ntlm);
        assert_eq!(hash, "8846f7eaee8fb117ad06bdd830b7586c");
    }
}
