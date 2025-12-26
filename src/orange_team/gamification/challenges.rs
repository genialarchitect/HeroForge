//! Security challenges management

use crate::orange_team::types::*;
use chrono::Utc;
use uuid::Uuid;

/// Challenge manager
pub struct ChallengeManager {
    challenges: Vec<SecurityChallenge>,
    attempts: Vec<ChallengeAttempt>,
}

impl ChallengeManager {
    /// Create a new challenge manager
    pub fn new() -> Self {
        Self {
            challenges: Vec::new(),
            attempts: Vec::new(),
        }
    }

    /// Create a new challenge
    pub fn create_challenge(
        &mut self,
        title: &str,
        description: &str,
        challenge_type: ChallengeType,
        difficulty: Difficulty,
        points_reward: u32,
    ) -> SecurityChallenge {
        let challenge = SecurityChallenge {
            id: Uuid::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            challenge_type,
            difficulty,
            points_reward,
            time_limit_minutes: None,
            max_attempts: None,
            content: serde_json::Value::Null,
            solution_hash: None,
            is_active: true,
            starts_at: None,
            ends_at: None,
            created_at: Utc::now(),
        };

        self.challenges.push(challenge.clone());
        challenge
    }

    /// Start an attempt
    pub fn start_attempt(&mut self, user_id: Uuid, challenge_id: Uuid) -> Option<ChallengeAttempt> {
        // Check if challenge exists and is active
        let challenge = self.challenges.iter().find(|c| c.id == challenge_id && c.is_active)?;

        // Check max attempts
        let user_attempts = self.attempts.iter()
            .filter(|a| a.user_id == user_id && a.challenge_id == challenge_id)
            .count() as u32;

        if let Some(max) = challenge.max_attempts {
            if user_attempts >= max {
                return None;
            }
        }

        let attempt = ChallengeAttempt {
            id: Uuid::new_v4(),
            user_id,
            challenge_id,
            status: ChallengeAttemptStatus::Attempted,
            score: None,
            time_spent_seconds: None,
            attempts_count: user_attempts + 1,
            completed_at: None,
            created_at: Utc::now(),
        };

        self.attempts.push(attempt.clone());
        Some(attempt)
    }

    /// Submit a challenge solution
    pub fn submit_solution(
        &mut self,
        attempt_id: Uuid,
        solution: &str,
        time_spent_seconds: u32,
    ) -> Option<ChallengeAttempt> {
        let attempt = self.attempts.iter_mut().find(|a| a.id == attempt_id)?;
        let challenge = self.challenges.iter().find(|c| c.id == attempt.challenge_id)?;

        attempt.time_spent_seconds = Some(time_spent_seconds);

        // Check solution
        let is_correct = if let Some(ref hash) = challenge.solution_hash {
            verify_solution(solution, hash)
        } else {
            // For quizzes or simulations, scoring is different
            true
        };

        if is_correct {
            attempt.status = ChallengeAttemptStatus::Completed;
            attempt.score = Some(100);
            attempt.completed_at = Some(Utc::now());
        } else {
            attempt.status = ChallengeAttemptStatus::Failed;
            attempt.score = Some(0);
        }

        Some(attempt.clone())
    }

    /// Get active challenges
    pub fn get_active_challenges(&self) -> Vec<&SecurityChallenge> {
        let now = Utc::now();
        self.challenges.iter()
            .filter(|c| {
                c.is_active
                    && c.starts_at.map(|s| s <= now).unwrap_or(true)
                    && c.ends_at.map(|e| e > now).unwrap_or(true)
            })
            .collect()
    }

    /// Get user's attempts
    pub fn get_user_attempts(&self, user_id: Uuid) -> Vec<&ChallengeAttempt> {
        self.attempts.iter().filter(|a| a.user_id == user_id).collect()
    }

    /// Check if user completed a challenge
    pub fn has_completed(&self, user_id: Uuid, challenge_id: Uuid) -> bool {
        self.attempts.iter().any(|a| {
            a.user_id == user_id
                && a.challenge_id == challenge_id
                && a.status == ChallengeAttemptStatus::Completed
        })
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a solution against its hash
fn verify_solution(solution: &str, expected_hash: &str) -> bool {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(solution.trim().to_lowercase().as_bytes());
    let result = format!("{:x}", hasher.finalize());
    result == expected_hash
}

/// Create a CTF challenge
pub fn create_ctf_challenge(
    title: &str,
    description: &str,
    difficulty: Difficulty,
    points: u32,
    flag: &str,
) -> SecurityChallenge {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(flag.trim().to_lowercase().as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    SecurityChallenge {
        id: Uuid::new_v4(),
        title: title.to_string(),
        description: description.to_string(),
        challenge_type: ChallengeType::Ctf,
        difficulty,
        points_reward: points,
        time_limit_minutes: None,
        max_attempts: None,
        content: serde_json::Value::Null,
        solution_hash: Some(hash),
        is_active: true,
        starts_at: None,
        ends_at: None,
        created_at: Utc::now(),
    }
}
