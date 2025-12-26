//! Leaderboard management

use crate::orange_team::types::*;
use uuid::Uuid;

/// Leaderboard type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderboardType {
    AllTime,
    Monthly,
    Weekly,
    Daily,
    Department,
}

/// Leaderboard manager
pub struct LeaderboardManager {
    entries: Vec<LeaderboardEntry>,
}

impl LeaderboardManager {
    /// Create a new leaderboard manager
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Update or add an entry
    pub fn update_entry(&mut self, entry: LeaderboardEntry) {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.user_id == entry.user_id) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        self.recalculate_ranks();
    }

    /// Recalculate all ranks
    fn recalculate_ranks(&mut self) {
        self.entries.sort_by(|a, b| b.points.cmp(&a.points));
        for (index, entry) in self.entries.iter_mut().enumerate() {
            entry.rank = (index + 1) as u32;
        }
    }

    /// Get top N entries
    pub fn get_top(&self, n: usize) -> Vec<&LeaderboardEntry> {
        self.entries.iter().take(n).collect()
    }

    /// Get a user's entry
    pub fn get_user_entry(&self, user_id: Uuid) -> Option<&LeaderboardEntry> {
        self.entries.iter().find(|e| e.user_id == user_id)
    }

    /// Get entries around a user (context leaderboard)
    pub fn get_context(&self, user_id: Uuid, radius: usize) -> Vec<&LeaderboardEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.user_id == user_id) {
            let start = pos.saturating_sub(radius);
            let end = (pos + radius + 1).min(self.entries.len());
            self.entries[start..end].iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Get total number of entries
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }
}

impl Default for LeaderboardManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a leaderboard entry
pub fn create_entry(
    user_id: Uuid,
    username: &str,
    points: u32,
    level: u32,
    badges_count: u32,
    streak_days: u32,
) -> LeaderboardEntry {
    LeaderboardEntry {
        rank: 0, // Will be calculated
        user_id,
        username: username.to_string(),
        points,
        level,
        badges_count,
        streak_days,
    }
}

/// Leaderboard summary for display
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaderboardSummary {
    pub leaderboard_type: LeaderboardType,
    pub total_participants: usize,
    pub top_entries: Vec<LeaderboardEntry>,
    pub user_entry: Option<LeaderboardEntry>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaderboard_ranking() {
        let mut manager = LeaderboardManager::new();

        manager.update_entry(create_entry(Uuid::new_v4(), "user1", 500, 2, 3, 5));
        manager.update_entry(create_entry(Uuid::new_v4(), "user2", 1000, 3, 5, 10));
        manager.update_entry(create_entry(Uuid::new_v4(), "user3", 750, 2, 4, 7));

        let top = manager.get_top(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].points, 1000);
        assert_eq!(top[0].rank, 1);
        assert_eq!(top[1].points, 750);
        assert_eq!(top[1].rank, 2);
    }
}
