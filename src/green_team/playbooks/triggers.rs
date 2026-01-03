//! Playbook trigger system
//!
//! Supports multiple trigger types:
//! - Alert-based triggers
//! - Manual execution
//! - Scheduled execution
//! - Webhook triggers
//! - API triggers

use crate::green_team::types::*;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Trigger type for playbooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookTriggerType {
    /// Triggered manually by a user
    Manual,
    /// Triggered by an alert
    Alert,
    /// Triggered on a schedule (cron)
    Schedule,
    /// Triggered by a webhook
    Webhook,
    /// Triggered via API
    Api,
}

/// Trigger configuration for a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    pub trigger_type: PlaybookTriggerType,
    /// Alert filter criteria (for alert triggers)
    pub alert_filter: Option<AlertFilter>,
    /// Schedule configuration (for scheduled triggers)
    pub schedule: Option<ScheduleConfig>,
    /// Webhook configuration (for webhook triggers)
    pub webhook_config: Option<WebhookConfig>,
    /// Auto-approval for low-risk actions
    pub auto_approve_low_risk: bool,
    /// Maximum concurrent runs
    pub max_concurrent_runs: Option<u32>,
}

/// Alert filter for trigger matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertFilter {
    /// Minimum severity to trigger
    pub min_severity: Option<Severity>,
    /// Alert categories to match
    pub categories: Option<Vec<String>>,
    /// Alert tags to match (any)
    pub tags_any: Option<Vec<String>>,
    /// Alert tags to match (all)
    pub tags_all: Option<Vec<String>>,
    /// Alert source systems
    pub sources: Option<Vec<String>>,
    /// Custom field filters
    pub custom_filters: Option<HashMap<String, String>>,
}

impl AlertFilter {
    /// Check if an alert matches this filter
    pub fn matches(&self, alert: &Alert) -> bool {
        // Check severity
        if let Some(ref min_sev) = self.min_severity {
            if alert.severity < *min_sev {
                return false;
            }
        }

        // Check categories
        if let Some(ref categories) = self.categories {
            if !categories.contains(&alert.category) {
                return false;
            }
        }

        // Check tags (any)
        if let Some(ref tags_any) = self.tags_any {
            if !alert.tags.iter().any(|t| tags_any.contains(t)) {
                return false;
            }
        }

        // Check tags (all)
        if let Some(ref tags_all) = self.tags_all {
            if !tags_all.iter().all(|t| alert.tags.contains(t)) {
                return false;
            }
        }

        // Check source
        if let Some(ref sources) = self.sources {
            if let Some(ref alert_source) = alert.source {
                if !sources.contains(alert_source) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// Schedule configuration (cron-based)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Cron expression (e.g., "0 0 * * *" for daily at midnight)
    pub cron_expression: String,
    /// Timezone for schedule (e.g., "UTC", "America/New_York")
    pub timezone: String,
    /// Whether the schedule is enabled
    pub enabled: bool,
    /// Next scheduled run time
    pub next_run: Option<DateTime<Utc>>,
}

impl ScheduleConfig {
    /// Check if the schedule should trigger now
    pub fn should_trigger(&self, now: DateTime<Utc>) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(next_run) = self.next_run {
            now >= next_run
        } else {
            false
        }
    }

    /// Calculate next run time from cron expression
    pub fn calculate_next_run(&mut self, from: DateTime<Utc>) {
        // Parse cron expression and calculate next run time
        // Cron format: minute hour day month weekday
        // Examples: "0 0 * * *" = daily at midnight, "0 */6 * * *" = every 6 hours

        let parts: Vec<&str> = self.cron_expression.trim().split_whitespace().collect();
        if parts.len() < 5 {
            // Invalid cron, default to 24 hours
            self.next_run = Some(from + chrono::Duration::hours(24));
            return;
        }

        let minute = Self::parse_cron_field(parts[0], 0, 59);
        let hour = Self::parse_cron_field(parts[1], 0, 23);
        let day = Self::parse_cron_field(parts[2], 1, 31);
        let month = Self::parse_cron_field(parts[3], 1, 12);
        let weekday = Self::parse_cron_field(parts[4], 0, 6);

        // Calculate next run based on cron fields
        // Start from current time and find next matching time
        let mut candidate = from + chrono::Duration::minutes(1);

        for _ in 0..525600 {
            // Max one year of iterations
            let cand_minute = candidate.minute();
            let cand_hour = candidate.hour();
            let cand_day = candidate.day();
            let cand_month = candidate.month();
            let cand_weekday = candidate.weekday().num_days_from_sunday();

            let minute_match = minute.is_empty() || minute.contains(&cand_minute);
            let hour_match = hour.is_empty() || hour.contains(&cand_hour);
            let day_match = day.is_empty() || day.contains(&cand_day);
            let month_match = month.is_empty() || month.contains(&cand_month);
            let weekday_match = weekday.is_empty() || weekday.contains(&cand_weekday);

            if minute_match && hour_match && day_match && month_match && weekday_match {
                self.next_run = Some(candidate);
                return;
            }

            candidate = candidate + chrono::Duration::minutes(1);
        }

        // Fallback to 24 hours if no match found
        self.next_run = Some(from + chrono::Duration::hours(24));
    }

    /// Parse a single cron field into a set of valid values
    fn parse_cron_field(field: &str, min: u32, max: u32) -> Vec<u32> {
        if field == "*" {
            return vec![]; // Empty means "any"
        }

        let mut values = Vec::new();

        // Handle step values (e.g., */5)
        if field.starts_with("*/") {
            if let Ok(step) = field[2..].parse::<u32>() {
                if step > 0 {
                    let mut val = min;
                    while val <= max {
                        values.push(val);
                        val += step;
                    }
                }
            }
            return values;
        }

        // Handle comma-separated values and ranges
        for part in field.split(',') {
            if let Some(dash_pos) = part.find('-') {
                // Range (e.g., 1-5)
                let start = part[..dash_pos].parse::<u32>().unwrap_or(min);
                let end = part[dash_pos + 1..].parse::<u32>().unwrap_or(max);
                for v in start..=end {
                    if v >= min && v <= max {
                        values.push(v);
                    }
                }
            } else {
                // Single value
                if let Ok(v) = part.parse::<u32>() {
                    if v >= min && v <= max {
                        values.push(v);
                    }
                }
            }
        }

        values
    }
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Unique webhook ID
    pub webhook_id: String,
    /// Secret for webhook authentication
    pub secret: Option<String>,
    /// Expected HTTP headers for validation
    pub expected_headers: Option<HashMap<String, String>>,
    /// Whether the webhook is enabled
    pub enabled: bool,
}

/// Alert that can trigger playbooks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Alert {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub tags: Vec<String>,
    pub source: Option<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Trigger manager for handling all playbook triggers
pub struct TriggerManager {
    /// Registered trigger configurations by playbook ID
    triggers: HashMap<Uuid, Vec<TriggerConfig>>,
    /// Active schedules
    schedules: HashMap<Uuid, ScheduleConfig>,
}

impl TriggerManager {
    /// Create a new trigger manager
    pub fn new() -> Self {
        Self {
            triggers: HashMap::new(),
            schedules: HashMap::new(),
        }
    }

    /// Register a trigger for a playbook
    pub fn register_trigger(&mut self, playbook_id: Uuid, config: TriggerConfig) {
        self.triggers
            .entry(playbook_id)
            .or_insert_with(Vec::new)
            .push(config);
    }

    /// Get all triggers for a playbook
    pub fn get_triggers(&self, playbook_id: &Uuid) -> Vec<&TriggerConfig> {
        self.triggers
            .get(playbook_id)
            .map(|configs| configs.iter().collect())
            .unwrap_or_default()
    }

    /// Find playbooks that should be triggered by an alert
    pub fn find_alert_triggers(&self, alert: &Alert) -> Vec<Uuid> {
        let mut matching_playbooks = Vec::new();

        for (playbook_id, triggers) in &self.triggers {
            for trigger in triggers {
                if trigger.trigger_type == PlaybookTriggerType::Alert {
                    if let Some(ref filter) = trigger.alert_filter {
                        if filter.matches(alert) {
                            matching_playbooks.push(*playbook_id);
                            break; // One match per playbook is enough
                        }
                    }
                }
            }
        }

        matching_playbooks
    }

    /// Register a schedule for a playbook
    pub fn register_schedule(&mut self, playbook_id: Uuid, mut schedule: ScheduleConfig) {
        schedule.calculate_next_run(Utc::now());
        self.schedules.insert(playbook_id, schedule);
    }

    /// Get playbooks that should be triggered by schedule
    pub fn get_scheduled_triggers(&self, now: DateTime<Utc>) -> Vec<Uuid> {
        self.schedules
            .iter()
            .filter_map(|(playbook_id, schedule)| {
                if schedule.should_trigger(now) {
                    Some(*playbook_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Update schedule next run time
    pub fn update_schedule_next_run(&mut self, playbook_id: &Uuid) {
        if let Some(schedule) = self.schedules.get_mut(playbook_id) {
            schedule.calculate_next_run(Utc::now());
        }
    }

    /// Remove a trigger
    pub fn remove_trigger(&mut self, playbook_id: &Uuid) {
        self.triggers.remove(playbook_id);
        self.schedules.remove(playbook_id);
    }
}

impl Default for TriggerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_filter_severity() {
        let filter = AlertFilter {
            min_severity: Some(Severity::High),
            categories: None,
            tags_any: None,
            tags_all: None,
            sources: None,
            custom_filters: None,
        };

        let high_alert = Alert {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            category: "malware".to_string(),
            tags: vec![],
            source: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let low_alert = Alert {
            severity: Severity::Low,
            ..high_alert.clone()
        };

        assert!(filter.matches(&high_alert));
        assert!(!filter.matches(&low_alert));
    }

    #[test]
    fn test_alert_filter_tags_any() {
        let filter = AlertFilter {
            min_severity: None,
            categories: None,
            tags_any: Some(vec!["ransomware".to_string(), "malware".to_string()]),
            tags_all: None,
            sources: None,
            custom_filters: None,
        };

        let matching_alert = Alert {
            id: Uuid::new_v4(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity: Severity::High,
            category: "threat".to_string(),
            tags: vec!["ransomware".to_string(), "encryption".to_string()],
            source: None,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let non_matching_alert = Alert {
            tags: vec!["phishing".to_string()],
            ..matching_alert.clone()
        };

        assert!(filter.matches(&matching_alert));
        assert!(!filter.matches(&non_matching_alert));
    }

    #[test]
    fn test_trigger_manager() {
        let mut manager = TriggerManager::new();
        let playbook_id = Uuid::new_v4();

        let trigger = TriggerConfig {
            trigger_type: PlaybookTriggerType::Alert,
            alert_filter: Some(AlertFilter {
                min_severity: Some(Severity::Critical),
                categories: None,
                tags_any: None,
                tags_all: None,
                sources: None,
                custom_filters: None,
            }),
            schedule: None,
            webhook_config: None,
            auto_approve_low_risk: true,
            max_concurrent_runs: Some(1),
        };

        manager.register_trigger(playbook_id, trigger);

        let alert = Alert {
            id: Uuid::new_v4(),
            title: "Critical Threat".to_string(),
            description: "Ransomware detected".to_string(),
            severity: Severity::Critical,
            category: "malware".to_string(),
            tags: vec!["ransomware".to_string()],
            source: Some("edr".to_string()),
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let matches = manager.find_alert_triggers(&alert);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], playbook_id);
    }
}
