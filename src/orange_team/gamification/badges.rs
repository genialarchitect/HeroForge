//! Badge management

use crate::orange_team::types::*;
use chrono::Utc;
use uuid::Uuid;

/// Badge manager for creating and awarding badges
pub struct BadgeManager {
    badges: Vec<TrainingBadge>,
    user_badges: Vec<UserBadge>,
}

impl BadgeManager {
    /// Create a new badge manager
    pub fn new() -> Self {
        Self {
            badges: Vec::new(),
            user_badges: Vec::new(),
        }
    }

    /// Create a new badge
    pub fn create_badge(
        &mut self,
        name: &str,
        description: &str,
        category: BadgeCategory,
        rarity: BadgeRarity,
    ) -> TrainingBadge {
        let badge = TrainingBadge {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: description.to_string(),
            icon_url: None,
            category,
            points_required: None,
            criteria: serde_json::Value::Null,
            rarity,
            created_at: Utc::now(),
        };

        self.badges.push(badge.clone());
        badge
    }

    /// Award a badge to a user
    pub fn award_badge(&mut self, user_id: Uuid, badge_id: Uuid) -> Option<UserBadge> {
        // Check if badge exists
        if !self.badges.iter().any(|b| b.id == badge_id) {
            return None;
        }

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
        Some(user_badge)
    }

    /// Get user's badges
    pub fn get_user_badges(&self, user_id: Uuid) -> Vec<&TrainingBadge> {
        self.user_badges
            .iter()
            .filter(|ub| ub.user_id == user_id)
            .filter_map(|ub| self.badges.iter().find(|b| b.id == ub.badge_id))
            .collect()
    }

    /// Get badges by category
    pub fn get_badges_by_category(&self, category: BadgeCategory) -> Vec<&TrainingBadge> {
        self.badges.iter().filter(|b| b.category == category).collect()
    }

    /// Get badges by rarity
    pub fn get_badges_by_rarity(&self, rarity: BadgeRarity) -> Vec<&TrainingBadge> {
        self.badges.iter().filter(|b| b.rarity == rarity).collect()
    }

    /// Check if user has a specific badge
    pub fn has_badge(&self, user_id: Uuid, badge_id: Uuid) -> bool {
        self.user_badges.iter().any(|ub| ub.user_id == user_id && ub.badge_id == badge_id)
    }

    /// Get all badges
    pub fn get_all_badges(&self) -> &[TrainingBadge] {
        &self.badges
    }
}

impl Default for BadgeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Badge progress tracking
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BadgeProgress {
    pub badge_id: Uuid,
    pub badge_name: String,
    pub current_value: u32,
    pub required_value: u32,
    pub progress_percent: f64,
    pub is_earned: bool,
}

/// Calculate badge progress for a user
pub fn calculate_badge_progress(
    badge: &TrainingBadge,
    current_value: u32,
    required_value: u32,
    is_earned: bool,
) -> BadgeProgress {
    let progress = if required_value > 0 {
        (current_value as f64 / required_value as f64 * 100.0).min(100.0)
    } else {
        if is_earned { 100.0 } else { 0.0 }
    };

    BadgeProgress {
        badge_id: badge.id,
        badge_name: badge.name.clone(),
        current_value,
        required_value,
        progress_percent: progress,
        is_earned,
    }
}
