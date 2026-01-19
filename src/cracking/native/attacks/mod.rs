//! Attack mode implementations
//!
//! Various password cracking attack strategies.

pub mod dictionary;
pub mod bruteforce;
pub mod rules;
pub mod mask;

pub use dictionary::DictionaryAttack;
pub use bruteforce::BruteForceAttack;
pub use rules::RuleBasedAttack;
pub use mask::MaskAttack;

use std::sync::Arc;
use tokio::sync::mpsc;
use crate::cracking::native::types::{HashAlgorithm, CrackResult, CrackProgress, NativeCrackConfig};

/// Trait for password cracking attacks
pub trait Attack: Send + Sync {
    /// Name of the attack
    fn name(&self) -> &'static str;

    /// Estimate total number of candidates (if possible)
    fn estimate_candidates(&self) -> Option<u64>;

    /// Generate password candidates
    fn candidates(&self) -> Box<dyn Iterator<Item = String> + Send>;
}

/// Common attack execution logic
pub struct AttackExecutor {
    /// Configuration
    config: NativeCrackConfig,
    /// Progress sender channel
    progress_tx: Option<mpsc::Sender<CrackProgress>>,
}

impl AttackExecutor {
    /// Create a new attack executor
    pub fn new(config: NativeCrackConfig) -> Self {
        Self {
            config,
            progress_tx: None,
        }
    }

    /// Set progress channel
    pub fn with_progress_channel(mut self, tx: mpsc::Sender<CrackProgress>) -> Self {
        self.progress_tx = Some(tx);
        self
    }

    /// Execute an attack against a list of hashes
    pub async fn execute(
        &self,
        attack: &dyn Attack,
        algorithm: Arc<dyn HashAlgorithm>,
        target_hashes: &[String],
    ) -> Vec<CrackResult> {
        use std::time::Instant;
        use rayon::prelude::*;

        let start_time = Instant::now();
        let mut results: Vec<CrackResult> = target_hashes
            .iter()
            .map(|h| CrackResult {
                hash: h.clone(),
                plaintext: None,
                duration: std::time::Duration::ZERO,
                candidates_tried: 0,
            })
            .collect();

        // Track which hashes still need cracking
        let mut uncracked: Vec<usize> = (0..target_hashes.len()).collect();
        let mut candidates_tested: u64 = 0;
        let total_candidates = attack.estimate_candidates();

        // Process candidates in batches
        let batch_size = self.config.batch_size;
        let mut batch: Vec<String> = Vec::with_capacity(batch_size);

        for candidate in attack.candidates() {
            batch.push(candidate);

            if batch.len() >= batch_size {
                // Process batch in parallel
                let found: Vec<(usize, String)> = uncracked
                    .par_iter()
                    .filter_map(|&idx| {
                        let hash = &target_hashes[idx];
                        for pwd in &batch {
                            if algorithm.verify(pwd.as_bytes(), hash) {
                                return Some((idx, pwd.clone()));
                            }
                        }
                        None
                    })
                    .collect();

                // Update results
                for (idx, plaintext) in found {
                    results[idx].plaintext = Some(plaintext);
                    results[idx].duration = start_time.elapsed();
                    results[idx].candidates_tried = candidates_tested + batch.len() as u64;
                    uncracked.retain(|&i| i != idx);
                }

                candidates_tested += batch.len() as u64;
                batch.clear();

                // Send progress update
                if let Some(ref tx) = self.progress_tx {
                    if candidates_tested % self.config.progress_interval == 0 {
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let speed = candidates_tested as f64 / elapsed;
                        let progress = CrackProgress {
                            total_hashes: target_hashes.len(),
                            cracked: target_hashes.len() - uncracked.len(),
                            speed,
                            candidates_tested,
                            total_candidates,
                            eta_seconds: total_candidates.map(|total| {
                                ((total - candidates_tested) as f64 / speed) as u64
                            }),
                        };
                        let _ = tx.try_send(progress);
                    }
                }

                // Check if all hashes are cracked
                if uncracked.is_empty() {
                    break;
                }

                // Check max candidates limit
                if self.config.max_candidates > 0 && candidates_tested >= self.config.max_candidates {
                    break;
                }
            }
        }

        // Process remaining batch
        if !batch.is_empty() && !uncracked.is_empty() {
            let found: Vec<(usize, String)> = uncracked
                .par_iter()
                .filter_map(|&idx| {
                    let hash = &target_hashes[idx];
                    for pwd in &batch {
                        if algorithm.verify(pwd.as_bytes(), hash) {
                            return Some((idx, pwd.clone()));
                        }
                    }
                    None
                })
                .collect();

            for (idx, plaintext) in found {
                results[idx].plaintext = Some(plaintext);
                results[idx].duration = start_time.elapsed();
                results[idx].candidates_tried = candidates_tested + batch.len() as u64;
            }
        }

        results
    }

    /// Execute attack synchronously (for simpler use cases)
    pub fn execute_sync(
        &self,
        attack: &dyn Attack,
        algorithm: Arc<dyn HashAlgorithm>,
        target_hashes: &[String],
    ) -> Vec<CrackResult> {
        use std::time::Instant;

        let start_time = Instant::now();
        let mut results: Vec<CrackResult> = target_hashes
            .iter()
            .map(|h| CrackResult {
                hash: h.clone(),
                plaintext: None,
                duration: std::time::Duration::ZERO,
                candidates_tried: 0,
            })
            .collect();

        let mut uncracked: Vec<usize> = (0..target_hashes.len()).collect();
        let mut candidates_tested: u64 = 0;

        for candidate in attack.candidates() {
            for &idx in &uncracked {
                if algorithm.verify(candidate.as_bytes(), &target_hashes[idx]) {
                    results[idx].plaintext = Some(candidate.clone());
                    results[idx].duration = start_time.elapsed();
                    results[idx].candidates_tried = candidates_tested;
                }
            }

            // Remove cracked hashes
            uncracked.retain(|&idx| results[idx].plaintext.is_none());

            candidates_tested += 1;

            if uncracked.is_empty() {
                break;
            }

            if self.config.max_candidates > 0 && candidates_tested >= self.config.max_candidates {
                break;
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cracking::native::hashes::Md5Hash;

    #[test]
    fn test_attack_executor_sync() {
        let config = NativeCrackConfig {
            batch_size: 100,
            max_candidates: 10000,
            ..Default::default()
        };
        let executor = AttackExecutor::new(config);

        // Create a simple dictionary attack
        let attack = DictionaryAttack::from_list(vec![
            "password".to_string(),
            "123456".to_string(),
            "admin".to_string(),
            "hello".to_string(),
        ]);

        let algorithm = Arc::new(Md5Hash);

        // MD5 of "hello" = 5d41402abc4b2a76b9719d911017c592
        let hashes = vec!["5d41402abc4b2a76b9719d911017c592".to_string()];

        let results = executor.execute_sync(&attack, algorithm, &hashes);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plaintext, Some("hello".to_string()));
    }
}
