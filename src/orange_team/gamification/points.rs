//! Point system management

use crate::orange_team::types::*;
use chrono::Utc;
use uuid::Uuid;

/// Point values for various activities
pub struct PointValues {
    pub course_completed: i32,
    pub quiz_passed: i32,
    pub module_completed: i32,
    pub challenge_won: i32,
    pub streak_bonus_7days: i32,
    pub streak_bonus_30days: i32,
    pub first_login: i32,
    pub profile_complete: i32,
    pub badge_earned: i32,
    pub referral_bonus: i32,
    pub phishing_reported: i32,
    pub perfect_quiz: i32,
}

impl Default for PointValues {
    fn default() -> Self {
        Self {
            course_completed: 100,
            quiz_passed: 50,
            module_completed: 25,
            challenge_won: 200,
            streak_bonus_7days: 50,
            streak_bonus_30days: 200,
            first_login: 10,
            profile_complete: 25,
            badge_earned: 25,
            referral_bonus: 100,
            phishing_reported: 30,
            perfect_quiz: 75,
        }
    }
}

/// Points calculator for various achievements
pub struct PointsCalculator {
    values: PointValues,
}

impl PointsCalculator {
    /// Create a new points calculator
    pub fn new() -> Self {
        Self {
            values: PointValues::default(),
        }
    }

    /// Create with custom point values
    pub fn with_values(values: PointValues) -> Self {
        Self { values }
    }

    /// Calculate points for an activity
    pub fn calculate(&self, reason: PointReason) -> i32 {
        match reason {
            PointReason::CourseCompleted => self.values.course_completed,
            PointReason::QuizPassed => self.values.quiz_passed,
            PointReason::ModuleCompleted => self.values.module_completed,
            PointReason::ChallengeWon => self.values.challenge_won,
            PointReason::StreakBonus => self.values.streak_bonus_7days,
            PointReason::FirstLogin => self.values.first_login,
            PointReason::ProfileComplete => self.values.profile_complete,
            PointReason::BadgeEarned => self.values.badge_earned,
            PointReason::ReferralBonus => self.values.referral_bonus,
            PointReason::PhishingReported => self.values.phishing_reported,
        }
    }

    /// Calculate bonus points for quiz score
    pub fn quiz_bonus(&self, score: u32) -> i32 {
        if score == 100 {
            self.values.perfect_quiz
        } else if score >= 90 {
            25
        } else if score >= 80 {
            10
        } else {
            0
        }
    }
}

impl Default for PointsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a point transaction
pub fn create_transaction(user_id: Uuid, points: i32, reason: PointReason, reference_id: Option<Uuid>) -> PointTransaction {
    PointTransaction {
        id: Uuid::new_v4(),
        user_id,
        points,
        reason,
        reference_id,
        created_at: Utc::now(),
    }
}
