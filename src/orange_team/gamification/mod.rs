//! Gamification module - Points, badges, and leaderboards

pub mod points;
pub mod badges;
pub mod leaderboards;
pub mod challenges;

pub use points::*;
pub use badges::*;
pub use leaderboards::*;
pub use challenges::*;

use crate::orange_team::types::*;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

/// Gamification engine for managing points, badges, and achievements
pub struct GamificationEngine {
    user_points: HashMap<Uuid, UserPoints>,
    user_badges: Vec<UserBadge>,
    badges: Vec<TrainingBadge>,
    transactions: Vec<PointTransaction>,
}

/// User points record
#[derive(Debug, Clone)]
pub struct UserPoints {
    pub user_id: Uuid,
    pub total_points: u32,
    pub level: u32,
    pub streak_days: u32,
    pub last_activity: Option<chrono::DateTime<Utc>>,
}

impl GamificationEngine {
    /// Create a new gamification engine
    pub fn new() -> Self {
        Self {
            user_points: HashMap::new(),
            user_badges: Vec::new(),
            badges: create_default_badges(),
            transactions: Vec::new(),
        }
    }

    /// Award points to a user
    pub fn award_points(&mut self, user_id: Uuid, points: i32, reason: PointReason, reference_id: Option<Uuid>) -> PointTransaction {
        let transaction = PointTransaction {
            id: Uuid::new_v4(),
            user_id,
            points,
            reason,
            reference_id,
            created_at: Utc::now(),
        };

        // Update user total
        let entry = self.user_points.entry(user_id).or_insert(UserPoints {
            user_id,
            total_points: 0,
            level: 1,
            streak_days: 0,
            last_activity: None,
        });

        if points > 0 {
            entry.total_points += points as u32;
        } else if entry.total_points as i32 + points >= 0 {
            entry.total_points = (entry.total_points as i32 + points) as u32;
        } else {
            entry.total_points = 0;
        }

        // Update level
        entry.level = calculate_level(entry.total_points);
        entry.last_activity = Some(Utc::now());

        // Extract values before releasing the borrow
        let total_points = entry.total_points;
        let level = entry.level;

        self.transactions.push(transaction.clone());

        // Check for badge unlocks
        self.check_badge_unlocks(user_id, total_points, level);

        transaction
    }

    /// Get user's gamification profile
    pub fn get_profile(&self, user_id: Uuid) -> GamificationProfile {
        let points_data = self.user_points.get(&user_id);

        let earned_badges: Vec<TrainingBadge> = self
            .user_badges
            .iter()
            .filter(|ub| ub.user_id == user_id)
            .filter_map(|ub| self.badges.iter().find(|b| b.id == ub.badge_id))
            .cloned()
            .collect();

        let (points, level, streak) = points_data
            .map(|p| (p.total_points, p.level, p.streak_days))
            .unwrap_or((0, 1, 0));

        GamificationProfile {
            user_id,
            points,
            level,
            streak_days: streak,
            badges: earned_badges,
            rank: self.calculate_rank(user_id),
            next_level_points: points_for_level(level + 1),
            last_activity_at: points_data.and_then(|p| p.last_activity),
        }
    }

    /// Update user's streak
    pub fn update_streak(&mut self, user_id: Uuid) -> u32 {
        let entry = self.user_points.entry(user_id).or_insert(UserPoints {
            user_id,
            total_points: 0,
            level: 1,
            streak_days: 0,
            last_activity: None,
        });

        let now = Utc::now();
        let last_activity = entry.last_activity;

        let streak = match last_activity {
            Some(last) => {
                let days_since = (now - last).num_days();
                if days_since == 1 {
                    entry.streak_days + 1
                } else if days_since == 0 {
                    entry.streak_days
                } else {
                    1
                }
            }
            None => 1,
        };

        entry.streak_days = streak;
        entry.last_activity = Some(now);

        // Award streak bonus
        if streak % 7 == 0 {
            self.award_points(user_id, 50, PointReason::StreakBonus, None);
        }

        streak
    }

    /// Check and award badges based on achievements
    fn check_badge_unlocks(&mut self, user_id: Uuid, points: u32, level: u32) {
        let badges_to_award: Vec<Uuid> = self
            .badges
            .iter()
            .filter(|badge| {
                // Check if user already has this badge
                if self.user_badges.iter().any(|ub| ub.user_id == user_id && ub.badge_id == badge.id) {
                    return false;
                }

                // Check points requirement
                if let Some(required) = badge.points_required {
                    if points >= required {
                        return true;
                    }
                }

                // Check level-based badges
                if let Some(level_req) = badge.criteria.get("level_required").and_then(|v| v.as_u64()) {
                    if level as u64 >= level_req {
                        return true;
                    }
                }

                false
            })
            .map(|b| b.id)
            .collect();

        for badge_id in badges_to_award {
            self.award_badge(user_id, badge_id);
        }
    }

    /// Award a badge to a user
    pub fn award_badge(&mut self, user_id: Uuid, badge_id: Uuid) -> Option<UserBadge> {
        // Check if user already has this badge
        if self.user_badges.iter().any(|ub| ub.user_id == user_id && ub.badge_id == badge_id) {
            return None;
        }

        let user_badge = UserBadge {
            id: Uuid::new_v4(),
            user_id,
            badge_id,
            earned_at: Utc::now(),
        };

        self.user_badges.push(user_badge.clone());

        // Award points for badge
        self.award_points(user_id, 25, PointReason::BadgeEarned, Some(badge_id));

        Some(user_badge)
    }

    /// Calculate user's rank on the leaderboard
    fn calculate_rank(&self, user_id: Uuid) -> u32 {
        let mut all_points: Vec<_> = self.user_points.values().collect();
        all_points.sort_by(|a, b| b.total_points.cmp(&a.total_points));

        all_points
            .iter()
            .position(|p| p.user_id == user_id)
            .map(|pos| (pos + 1) as u32)
            .unwrap_or(0)
    }

    /// Get all available badges
    pub fn get_all_badges(&self) -> &[TrainingBadge] {
        &self.badges
    }

    /// Get point transactions for a user
    pub fn get_transactions(&self, user_id: Uuid, limit: usize) -> Vec<&PointTransaction> {
        self.transactions
            .iter()
            .filter(|t| t.user_id == user_id)
            .rev()
            .take(limit)
            .collect()
    }
}

impl Default for GamificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate level from points
fn calculate_level(points: u32) -> u32 {
    // Level up every 1000 points, starting from level 1
    (points / 1000) + 1
}

/// Get points required for a level
fn points_for_level(level: u32) -> u32 {
    if level <= 1 {
        0
    } else {
        (level - 1) * 1000
    }
}

/// Create default badges
fn create_default_badges() -> Vec<TrainingBadge> {
    vec![
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "First Steps".to_string(),
            description: "Complete your first training course".to_string(),
            icon_url: None,
            category: BadgeCategory::Completion,
            points_required: None,
            criteria: serde_json::json!({"courses_completed": 1}),
            rarity: BadgeRarity::Common,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Century Club".to_string(),
            description: "Earn 100 points".to_string(),
            icon_url: None,
            category: BadgeCategory::Achievement,
            points_required: Some(100),
            criteria: serde_json::json!({}),
            rarity: BadgeRarity::Common,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Point Collector".to_string(),
            description: "Earn 500 points".to_string(),
            icon_url: None,
            category: BadgeCategory::Achievement,
            points_required: Some(500),
            criteria: serde_json::json!({}),
            rarity: BadgeRarity::Uncommon,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Security Expert".to_string(),
            description: "Earn 1000 points".to_string(),
            icon_url: None,
            category: BadgeCategory::Achievement,
            points_required: Some(1000),
            criteria: serde_json::json!({}),
            rarity: BadgeRarity::Rare,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Week Warrior".to_string(),
            description: "Maintain a 7-day streak".to_string(),
            icon_url: None,
            category: BadgeCategory::Streak,
            points_required: None,
            criteria: serde_json::json!({"streak_days": 7}),
            rarity: BadgeRarity::Uncommon,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Month Master".to_string(),
            description: "Maintain a 30-day streak".to_string(),
            icon_url: None,
            category: BadgeCategory::Streak,
            points_required: None,
            criteria: serde_json::json!({"streak_days": 30}),
            rarity: BadgeRarity::Epic,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Phishing Fighter".to_string(),
            description: "Report 5 phishing emails".to_string(),
            icon_url: None,
            category: BadgeCategory::Special,
            points_required: None,
            criteria: serde_json::json!({"phishing_reported": 5}),
            rarity: BadgeRarity::Rare,
            created_at: Utc::now(),
        },
        TrainingBadge {
            id: Uuid::new_v4(),
            name: "Quiz Master".to_string(),
            description: "Score 100% on 5 quizzes".to_string(),
            icon_url: None,
            category: BadgeCategory::Achievement,
            points_required: None,
            criteria: serde_json::json!({"perfect_quizzes": 5}),
            rarity: BadgeRarity::Epic,
            created_at: Utc::now(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_award_points() {
        let mut engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();

        let tx = engine.award_points(user_id, 100, PointReason::CourseCompleted, None);

        assert_eq!(tx.points, 100);
        assert_eq!(tx.reason, PointReason::CourseCompleted);

        let profile = engine.get_profile(user_id);
        assert!(profile.points >= 100); // May have badge bonus
    }

    #[test]
    fn test_level_calculation() {
        assert_eq!(calculate_level(0), 1);
        assert_eq!(calculate_level(999), 1);
        assert_eq!(calculate_level(1000), 2);
        assert_eq!(calculate_level(2500), 3);
    }
}
