//! Real-time Correlation Engine for HeroForge SIEM
//!
//! This module provides advanced event correlation capabilities including:
//! - Time-window based correlation (e.g., 5 failed logins in 1 minute)
//! - Sequence detection (event A followed by B within X seconds)
//! - Threshold-based alerting
//! - Pattern-based correlation
//!
//! # Architecture
//!
//! The correlation engine maintains in-memory state for active correlation
//! windows and evaluates incoming log events against defined rules.
//!
//! ```text
//! +------------------+     +------------------+     +------------------+
//! |   Log Events     | --> | Correlation      | --> |   Alerts         |
//! |                  |     | Engine           |     |                  |
//! +------------------+     +------------------+     +------------------+
//!                                 |
//!                                 v
//!                         +------------------+
//!                         | Correlation State|
//!                         | (Time Windows)   |
//!                         +------------------+
//! ```

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::types::{LogEntry, SiemSeverity};

// ============================================================================
// Correlation Rule Types
// ============================================================================

/// Type of correlation rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationRuleType {
    /// Count events matching criteria within time window
    Threshold,
    /// Detect sequence of events in order
    Sequence,
    /// Detect events from same source matching multiple patterns
    Pattern,
    /// Detect events within time proximity
    TimeProximity,
    /// Detect spike in event rate
    Spike,
    /// Detect unique value count exceeding threshold
    UniqueValue,
}

impl CorrelationRuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Threshold => "threshold",
            Self::Sequence => "sequence",
            Self::Pattern => "pattern",
            Self::TimeProximity => "time_proximity",
            Self::Spike => "spike",
            Self::UniqueValue => "unique_value",
        }
    }
}

impl Default for CorrelationRuleType {
    fn default() -> Self {
        Self::Threshold
    }
}

/// A correlation rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: CorrelationRuleType,
    /// Conditions for matching events (JSON structure)
    pub conditions: CorrelationConditions,
    /// Time window in seconds
    pub time_window_secs: i64,
    /// Threshold count (for threshold rules)
    pub threshold: Option<i64>,
    /// Fields to group by (e.g., source_ip, user)
    pub group_by: Vec<String>,
    /// Severity of generated alerts
    pub severity: SiemSeverity,
    /// Whether rule is enabled
    pub enabled: bool,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<String>,
}

/// Conditions for correlation matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConditions {
    /// Event patterns to match (for threshold/pattern rules)
    #[serde(default)]
    pub patterns: Vec<EventPattern>,
    /// Sequence of events (for sequence rules)
    #[serde(default)]
    pub sequence: Vec<SequenceStep>,
    /// Field conditions (field -> value pattern)
    #[serde(default)]
    pub field_conditions: HashMap<String, FieldCondition>,
    /// Required source types
    #[serde(default)]
    pub source_types: Vec<String>,
    /// Minimum severity to match
    pub min_severity: Option<SiemSeverity>,
}

impl Default for CorrelationConditions {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            sequence: Vec::new(),
            field_conditions: HashMap::new(),
            source_types: Vec::new(),
            min_severity: None,
        }
    }
}

/// A pattern to match against events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPattern {
    pub name: String,
    pub description: Option<String>,
    /// Field conditions for this pattern
    pub conditions: HashMap<String, FieldCondition>,
    /// Whether this pattern is required
    pub required: bool,
}

/// A step in a sequence detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceStep {
    pub name: String,
    /// Pattern to match for this step
    pub pattern: EventPattern,
    /// Maximum time since previous step (seconds)
    pub max_span: Option<i64>,
    /// Minimum time since previous step (seconds)
    pub min_span: Option<i64>,
}

/// Condition for a field match
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldCondition {
    /// Exact match
    Exact(String),
    /// Match any of the values
    OneOf(Vec<String>),
    /// Contains substring
    Contains(ContainsCondition),
    /// Regex match
    Regex(RegexCondition),
    /// Numeric comparison
    Numeric(NumericCondition),
    /// Not equal
    NotEqual(NotEqualCondition),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainsCondition {
    pub contains: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexCondition {
    pub regex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumericCondition {
    pub op: String, // "gt", "gte", "lt", "lte", "eq"
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotEqualCondition {
    pub not_equal: String,
}

// ============================================================================
// Correlation State
// ============================================================================

/// State for a correlation window
#[derive(Debug, Clone)]
pub struct CorrelationWindow {
    pub rule_id: String,
    pub group_key: String,
    /// Events in this window
    pub events: VecDeque<WindowEvent>,
    /// Window start time
    pub window_start: DateTime<Utc>,
    /// Window expiration time
    pub expires_at: DateTime<Utc>,
    /// Sequence tracking (current step index)
    pub sequence_step: usize,
    /// Last alert time (for dedup)
    pub last_alert_at: Option<DateTime<Utc>>,
}

/// A simplified event for window storage
#[derive(Debug, Clone)]
pub struct WindowEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub fields: HashMap<String, String>,
    pub matched_pattern: Option<String>,
}

/// Statistics for the correlation engine
#[derive(Debug, Clone, Default, Serialize)]
pub struct CorrelationStats {
    pub active_windows: usize,
    pub events_processed: u64,
    pub alerts_generated: u64,
    pub rules_evaluated: u64,
    pub windows_expired: u64,
}

// ============================================================================
// Correlation Engine
// ============================================================================

/// Real-time correlation engine
pub struct CorrelationEngine {
    /// Active correlation rules
    rules: Arc<RwLock<HashMap<String, CorrelationRule>>>,
    /// Active correlation windows (rule_id -> group_key -> window)
    windows: Arc<RwLock<HashMap<String, HashMap<String, CorrelationWindow>>>>,
    /// Engine statistics
    stats: Arc<RwLock<CorrelationStats>>,
    /// Alert callback
    alert_handler: Option<Arc<dyn Fn(CorrelationAlert) + Send + Sync>>,
}

/// Alert generated by correlation
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationAlert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: SiemSeverity,
    pub title: String,
    pub description: String,
    pub event_ids: Vec<String>,
    pub event_count: i64,
    pub group_key: String,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub context: HashMap<String, serde_json::Value>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            windows: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CorrelationStats::default())),
            alert_handler: None,
        }
    }

    /// Set an alert handler callback
    pub fn with_alert_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(CorrelationAlert) + Send + Sync + 'static,
    {
        self.alert_handler = Some(Arc::new(handler));
        self
    }

    /// Add a correlation rule
    pub async fn add_rule(&self, rule: CorrelationRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    /// Remove a correlation rule
    pub async fn remove_rule(&self, rule_id: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let removed = rules.remove(rule_id).is_some();

        // Also clean up windows for this rule
        if removed {
            let mut windows = self.windows.write().await;
            windows.remove(rule_id);
        }

        Ok(removed)
    }

    /// Update a correlation rule
    pub async fn update_rule(&self, rule: CorrelationRule) -> Result<()> {
        let mut rules = self.rules.write().await;
        rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    /// Get all rules
    pub async fn get_rules(&self) -> Vec<CorrelationRule> {
        let rules = self.rules.read().await;
        rules.values().cloned().collect()
    }

    /// Get a rule by ID
    pub async fn get_rule(&self, rule_id: &str) -> Option<CorrelationRule> {
        let rules = self.rules.read().await;
        rules.get(rule_id).cloned()
    }

    /// Process a log event
    pub async fn process_event(&self, entry: &LogEntry) -> Vec<CorrelationAlert> {
        let rules = self.rules.read().await;
        let mut alerts = Vec::new();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.events_processed += 1;
        }

        // Evaluate each enabled rule
        for rule in rules.values() {
            if !rule.enabled {
                continue;
            }

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.rules_evaluated += 1;
            }

            // Check if event matches rule conditions
            if !self.event_matches_rule(entry, rule) {
                continue;
            }

            // Process based on rule type
            let alert = match rule.rule_type {
                CorrelationRuleType::Threshold => {
                    self.process_threshold_rule(entry, rule).await
                }
                CorrelationRuleType::Sequence => {
                    self.process_sequence_rule(entry, rule).await
                }
                CorrelationRuleType::Pattern => {
                    self.process_pattern_rule(entry, rule).await
                }
                CorrelationRuleType::TimeProximity => {
                    self.process_proximity_rule(entry, rule).await
                }
                CorrelationRuleType::Spike => {
                    self.process_spike_rule(entry, rule).await
                }
                CorrelationRuleType::UniqueValue => {
                    self.process_unique_value_rule(entry, rule).await
                }
            };

            if let Some(a) = alert {
                if let Some(ref handler) = self.alert_handler {
                    handler(a.clone());
                }
                alerts.push(a);
            }
        }

        alerts
    }

    /// Check if an event matches the basic rule conditions
    fn event_matches_rule(&self, entry: &LogEntry, rule: &CorrelationRule) -> bool {
        let conditions = &rule.conditions;

        // Check minimum severity
        if let Some(min_sev) = conditions.min_severity {
            if entry.severity < min_sev {
                return false;
            }
        }

        // Check source types (if specified)
        if !conditions.source_types.is_empty() {
            let matches_source = conditions.source_types.iter()
                .any(|st| entry.source_id.contains(st));
            if !matches_source {
                return false;
            }
        }

        // Check field conditions
        for (field, condition) in &conditions.field_conditions {
            if !self.check_field_condition(entry, field, condition) {
                return false;
            }
        }

        true
    }

    /// Check a field condition against an event
    fn check_field_condition(&self, entry: &LogEntry, field: &str, condition: &FieldCondition) -> bool {
        let value = self.get_field_value(entry, field);

        match condition {
            FieldCondition::Exact(expected) => {
                value.as_deref() == Some(expected.as_str())
            }
            FieldCondition::OneOf(options) => {
                value.as_ref().map(|v| options.contains(v)).unwrap_or(false)
            }
            FieldCondition::Contains(c) => {
                value.as_ref().map(|v| v.contains(&c.contains)).unwrap_or(false)
            }
            FieldCondition::Regex(r) => {
                if let Ok(regex) = regex::Regex::new(&r.regex) {
                    value.as_ref().map(|v| regex.is_match(v)).unwrap_or(false)
                } else {
                    false
                }
            }
            FieldCondition::Numeric(n) => {
                let Some(v) = value.as_ref().and_then(|s| s.parse::<i64>().ok()) else {
                    return false;
                };
                match n.op.as_str() {
                    "gt" => v > n.value,
                    "gte" => v >= n.value,
                    "lt" => v < n.value,
                    "lte" => v <= n.value,
                    "eq" => v == n.value,
                    _ => false,
                }
            }
            FieldCondition::NotEqual(ne) => {
                value.as_ref().map(|v| v != &ne.not_equal).unwrap_or(true)
            }
        }
    }

    /// Get a field value from a log entry
    fn get_field_value(&self, entry: &LogEntry, field: &str) -> Option<String> {
        match field {
            "source_ip" => entry.source_ip.map(|ip| ip.to_string()),
            "destination_ip" => entry.destination_ip.map(|ip| ip.to_string()),
            "source_port" => entry.source_port.map(|p| p.to_string()),
            "destination_port" => entry.destination_port.map(|p| p.to_string()),
            "hostname" => entry.hostname.clone(),
            "user" => entry.user.clone(),
            "application" => entry.application.clone(),
            "category" => entry.category.clone(),
            "action" => entry.action.clone(),
            "outcome" => entry.outcome.clone(),
            "message" => Some(entry.message.clone()),
            "severity" => Some(entry.severity.as_str().to_string()),
            _ => {
                // Check structured data
                entry.structured_data.get(field).and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else {
                        Some(v.to_string())
                    }
                })
            }
        }
    }

    /// Build group key from event based on group_by fields
    fn build_group_key(&self, entry: &LogEntry, rule: &CorrelationRule) -> String {
        if rule.group_by.is_empty() {
            return "default".to_string();
        }

        rule.group_by.iter()
            .filter_map(|field| self.get_field_value(entry, field))
            .collect::<Vec<_>>()
            .join("|")
    }

    /// Convert log entry to window event
    fn entry_to_window_event(&self, entry: &LogEntry) -> WindowEvent {
        let mut fields = HashMap::new();

        if let Some(ip) = entry.source_ip {
            fields.insert("source_ip".to_string(), ip.to_string());
        }
        if let Some(ip) = entry.destination_ip {
            fields.insert("destination_ip".to_string(), ip.to_string());
        }
        if let Some(ref hostname) = entry.hostname {
            fields.insert("hostname".to_string(), hostname.clone());
        }
        if let Some(ref user) = entry.user {
            fields.insert("user".to_string(), user.clone());
        }
        if let Some(ref app) = entry.application {
            fields.insert("application".to_string(), app.clone());
        }
        if let Some(ref category) = entry.category {
            fields.insert("category".to_string(), category.clone());
        }
        if let Some(ref action) = entry.action {
            fields.insert("action".to_string(), action.clone());
        }
        if let Some(ref outcome) = entry.outcome {
            fields.insert("outcome".to_string(), outcome.clone());
        }

        WindowEvent {
            id: entry.id.clone(),
            timestamp: entry.timestamp,
            fields,
            matched_pattern: None,
        }
    }

    /// Process a threshold correlation rule
    async fn process_threshold_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        let threshold = rule.threshold.unwrap_or(5);
        let group_key = self.build_group_key(entry, rule);
        let now = Utc::now();
        let window_duration = Duration::seconds(rule.time_window_secs);

        let mut windows = self.windows.write().await;
        let rule_windows = windows.entry(rule.id.clone()).or_insert_with(HashMap::new);

        // Get or create window
        let window = rule_windows.entry(group_key.clone()).or_insert_with(|| {
            CorrelationWindow {
                rule_id: rule.id.clone(),
                group_key: group_key.clone(),
                events: VecDeque::new(),
                window_start: now,
                expires_at: now + window_duration,
                sequence_step: 0,
                last_alert_at: None,
            }
        });

        // Remove expired events
        while let Some(front) = window.events.front() {
            if now - front.timestamp > window_duration {
                window.events.pop_front();
            } else {
                break;
            }
        }

        // Add new event
        window.events.push_back(self.entry_to_window_event(entry));

        // Check if threshold is exceeded
        let event_count = window.events.len() as i64;
        if event_count >= threshold {
            // Prevent alert spam - wait at least half the window before re-alerting
            if let Some(last_alert) = window.last_alert_at {
                if now - last_alert < window_duration / 2 {
                    return None;
                }
            }

            window.last_alert_at = Some(now);

            // Generate alert
            let event_ids: Vec<String> = window.events.iter()
                .map(|e| e.id.clone())
                .collect();
            let first_event = window.events.front()
                .map(|e| e.timestamp)
                .unwrap_or(now);
            let last_event = window.events.back()
                .map(|e| e.timestamp)
                .unwrap_or(now);

            let alert = CorrelationAlert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                title: format!("{} - {} events in {} seconds",
                    rule.name, event_count, rule.time_window_secs),
                description: rule.description.clone().unwrap_or_else(|| {
                    format!("Threshold exceeded: {} events (threshold: {}) within {} seconds for group: {}",
                        event_count, threshold, rule.time_window_secs, group_key)
                }),
                event_ids,
                event_count,
                group_key,
                first_event,
                last_event,
                created_at: now,
                context: HashMap::new(),
                mitre_tactics: rule.mitre_tactics.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            };

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }

            return Some(alert);
        }

        None
    }

    /// Process a sequence correlation rule
    async fn process_sequence_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        if rule.conditions.sequence.is_empty() {
            return None;
        }

        let group_key = self.build_group_key(entry, rule);
        let now = Utc::now();
        let window_duration = Duration::seconds(rule.time_window_secs);

        let mut windows = self.windows.write().await;
        let rule_windows = windows.entry(rule.id.clone()).or_insert_with(HashMap::new);

        let window = rule_windows.entry(group_key.clone()).or_insert_with(|| {
            CorrelationWindow {
                rule_id: rule.id.clone(),
                group_key: group_key.clone(),
                events: VecDeque::new(),
                window_start: now,
                expires_at: now + window_duration,
                sequence_step: 0,
                last_alert_at: None,
            }
        });

        // Check if window expired - reset sequence
        if now > window.expires_at {
            window.events.clear();
            window.sequence_step = 0;
            window.window_start = now;
            window.expires_at = now + window_duration;
        }

        // Check if event matches current step
        let current_step = &rule.conditions.sequence.get(window.sequence_step)?;

        // Check time constraints for subsequent steps
        if window.sequence_step > 0 {
            if let Some(last_event) = window.events.back() {
                let span = (now - last_event.timestamp).num_seconds();

                if let Some(max_span) = current_step.max_span {
                    if span > max_span {
                        // Sequence broken - reset
                        window.events.clear();
                        window.sequence_step = 0;
                        window.window_start = now;
                        window.expires_at = now + window_duration;
                        return None;
                    }
                }

                if let Some(min_span) = current_step.min_span {
                    if span < min_span {
                        // Too soon for next step
                        return None;
                    }
                }
            }
        }

        // Check if event matches the pattern for this step
        let matches = current_step.pattern.conditions.iter().all(|(field, condition)| {
            self.check_field_condition(entry, field, condition)
        });

        if !matches {
            return None;
        }

        // Event matches - add to sequence
        let mut event = self.entry_to_window_event(entry);
        event.matched_pattern = Some(current_step.name.clone());
        window.events.push_back(event);
        window.sequence_step += 1;

        // Check if sequence is complete
        if window.sequence_step >= rule.conditions.sequence.len() {
            // Sequence complete - generate alert
            let event_ids: Vec<String> = window.events.iter()
                .map(|e| e.id.clone())
                .collect();
            let first_event = window.events.front()
                .map(|e| e.timestamp)
                .unwrap_or(now);

            let alert = CorrelationAlert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                title: format!("{} - Sequence completed", rule.name),
                description: rule.description.clone().unwrap_or_else(|| {
                    format!("Event sequence detected for group: {}", group_key)
                }),
                event_ids,
                event_count: window.events.len() as i64,
                group_key: group_key.clone(),
                first_event,
                last_event: now,
                created_at: now,
                context: HashMap::new(),
                mitre_tactics: rule.mitre_tactics.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            };

            // Reset window for next sequence
            window.events.clear();
            window.sequence_step = 0;
            window.window_start = now;
            window.expires_at = now + window_duration;

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }

            return Some(alert);
        }

        None
    }

    /// Process a pattern correlation rule
    async fn process_pattern_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        if rule.conditions.patterns.is_empty() {
            return None;
        }

        let group_key = self.build_group_key(entry, rule);
        let now = Utc::now();
        let window_duration = Duration::seconds(rule.time_window_secs);

        // Find which pattern(s) this event matches
        let mut matched_pattern: Option<String> = None;
        for pattern in &rule.conditions.patterns {
            let matches = pattern.conditions.iter().all(|(field, condition)| {
                self.check_field_condition(entry, field, condition)
            });
            if matches {
                matched_pattern = Some(pattern.name.clone());
                break;
            }
        }

        let matched = matched_pattern?;

        let mut windows = self.windows.write().await;
        let rule_windows = windows.entry(rule.id.clone()).or_insert_with(HashMap::new);

        let window = rule_windows.entry(group_key.clone()).or_insert_with(|| {
            CorrelationWindow {
                rule_id: rule.id.clone(),
                group_key: group_key.clone(),
                events: VecDeque::new(),
                window_start: now,
                expires_at: now + window_duration,
                sequence_step: 0,
                last_alert_at: None,
            }
        });

        // Remove expired events
        while let Some(front) = window.events.front() {
            if now - front.timestamp > window_duration {
                window.events.pop_front();
            } else {
                break;
            }
        }

        // Add event with matched pattern
        let mut event = self.entry_to_window_event(entry);
        event.matched_pattern = Some(matched.clone());
        window.events.push_back(event);

        // Check if all required patterns have been seen
        let required_patterns: Vec<&String> = rule.conditions.patterns.iter()
            .filter(|p| p.required)
            .map(|p| &p.name)
            .collect();

        let seen_patterns: std::collections::HashSet<&String> = window.events.iter()
            .filter_map(|e| e.matched_pattern.as_ref())
            .collect();

        let all_required_seen = required_patterns.iter()
            .all(|p| seen_patterns.contains(p));

        if all_required_seen {
            // All required patterns matched - generate alert
            let event_ids: Vec<String> = window.events.iter()
                .map(|e| e.id.clone())
                .collect();
            let first_event = window.events.front()
                .map(|e| e.timestamp)
                .unwrap_or(now);

            let alert = CorrelationAlert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                title: format!("{} - Pattern correlation matched", rule.name),
                description: rule.description.clone().unwrap_or_else(|| {
                    format!("All required patterns detected for group: {}", group_key)
                }),
                event_ids,
                event_count: window.events.len() as i64,
                group_key: group_key.clone(),
                first_event,
                last_event: now,
                created_at: now,
                context: HashMap::new(),
                mitre_tactics: rule.mitre_tactics.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            };

            // Reset window
            window.events.clear();

            // Update stats
            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }

            return Some(alert);
        }

        None
    }

    /// Process a time proximity rule
    async fn process_proximity_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        // Similar to pattern rule but focuses on temporal proximity
        self.process_pattern_rule(entry, rule).await
    }

    /// Process a spike detection rule
    async fn process_spike_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        let group_key = self.build_group_key(entry, rule);
        let now = Utc::now();
        let window_duration = Duration::seconds(rule.time_window_secs);
        let threshold = rule.threshold.unwrap_or(10);

        let mut windows = self.windows.write().await;
        let rule_windows = windows.entry(rule.id.clone()).or_insert_with(HashMap::new);

        let window = rule_windows.entry(group_key.clone()).or_insert_with(|| {
            CorrelationWindow {
                rule_id: rule.id.clone(),
                group_key: group_key.clone(),
                events: VecDeque::new(),
                window_start: now,
                expires_at: now + window_duration,
                sequence_step: 0,
                last_alert_at: None,
            }
        });

        // Calculate baseline from previous windows (simplified - uses same window)
        let baseline_count = window.sequence_step as i64; // Using sequence_step as baseline

        // Remove expired events and add new one
        while let Some(front) = window.events.front() {
            if now - front.timestamp > window_duration {
                window.events.pop_front();
            } else {
                break;
            }
        }

        window.events.push_back(self.entry_to_window_event(entry));
        let current_count = window.events.len() as i64;

        // Detect spike: current count is significantly higher than baseline
        // Using simple threshold comparison for now
        if current_count >= threshold && current_count > baseline_count * 2 {
            // Prevent rapid re-alerting
            if let Some(last_alert) = window.last_alert_at {
                if now - last_alert < window_duration / 2 {
                    return None;
                }
            }

            window.last_alert_at = Some(now);
            window.sequence_step = current_count as usize; // Update baseline

            let event_ids: Vec<String> = window.events.iter()
                .map(|e| e.id.clone())
                .collect();

            let alert = CorrelationAlert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                title: format!("{} - Event spike detected", rule.name),
                description: format!("Event rate spike detected: {} events (baseline: {}) for group: {}",
                    current_count, baseline_count, group_key),
                event_ids,
                event_count: current_count,
                group_key,
                first_event: window.events.front().map(|e| e.timestamp).unwrap_or(now),
                last_event: now,
                created_at: now,
                context: HashMap::new(),
                mitre_tactics: rule.mitre_tactics.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            };

            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }

            return Some(alert);
        }

        // Update baseline
        window.sequence_step = current_count as usize;

        None
    }

    /// Process a unique value rule
    async fn process_unique_value_rule(
        &self,
        entry: &LogEntry,
        rule: &CorrelationRule,
    ) -> Option<CorrelationAlert> {
        let group_key = self.build_group_key(entry, rule);
        let now = Utc::now();
        let window_duration = Duration::seconds(rule.time_window_secs);
        let threshold = rule.threshold.unwrap_or(10);

        let mut windows = self.windows.write().await;
        let rule_windows = windows.entry(rule.id.clone()).or_insert_with(HashMap::new);

        let window = rule_windows.entry(group_key.clone()).or_insert_with(|| {
            CorrelationWindow {
                rule_id: rule.id.clone(),
                group_key: group_key.clone(),
                events: VecDeque::new(),
                window_start: now,
                expires_at: now + window_duration,
                sequence_step: 0,
                last_alert_at: None,
            }
        });

        // Remove expired events
        while let Some(front) = window.events.front() {
            if now - front.timestamp > window_duration {
                window.events.pop_front();
            } else {
                break;
            }
        }

        window.events.push_back(self.entry_to_window_event(entry));

        // Count unique values (using a specified field from conditions)
        // Default to counting unique destination ports for port scan detection
        let count_field = rule.group_by.first()
            .cloned()
            .unwrap_or_else(|| "destination_port".to_string());

        let unique_values: std::collections::HashSet<&String> = window.events.iter()
            .filter_map(|e| e.fields.get(&count_field))
            .collect();

        let unique_count = unique_values.len() as i64;

        if unique_count >= threshold {
            // Prevent rapid re-alerting
            if let Some(last_alert) = window.last_alert_at {
                if now - last_alert < window_duration / 2 {
                    return None;
                }
            }

            window.last_alert_at = Some(now);

            let event_ids: Vec<String> = window.events.iter()
                .map(|e| e.id.clone())
                .collect();

            let alert = CorrelationAlert {
                id: uuid::Uuid::new_v4().to_string(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                title: format!("{} - High unique value count", rule.name),
                description: format!("{} unique {} values detected for group: {}",
                    unique_count, count_field, group_key),
                event_ids,
                event_count: window.events.len() as i64,
                group_key,
                first_event: window.events.front().map(|e| e.timestamp).unwrap_or(now),
                last_event: now,
                created_at: now,
                context: HashMap::new(),
                mitre_tactics: rule.mitre_tactics.clone(),
                mitre_techniques: rule.mitre_techniques.clone(),
            };

            {
                let mut stats = self.stats.write().await;
                stats.alerts_generated += 1;
            }

            return Some(alert);
        }

        None
    }

    /// Cleanup expired windows
    pub async fn cleanup_expired_windows(&self) {
        let now = Utc::now();
        let mut windows = self.windows.write().await;
        let mut expired_count = 0u64;

        for rule_windows in windows.values_mut() {
            let expired_keys: Vec<String> = rule_windows.iter()
                .filter(|(_, w)| now > w.expires_at)
                .map(|(k, _)| k.clone())
                .collect();

            for key in expired_keys {
                rule_windows.remove(&key);
                expired_count += 1;
            }
        }

        if expired_count > 0 {
            let mut stats = self.stats.write().await;
            stats.windows_expired += expired_count;
        }
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> CorrelationStats {
        let stats = self.stats.read().await;
        let windows = self.windows.read().await;

        let active_windows: usize = windows.values()
            .map(|rw| rw.len())
            .sum();

        CorrelationStats {
            active_windows,
            ..stats.clone()
        }
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Built-in Correlation Rules
// ============================================================================

/// Get built-in correlation rules
pub fn get_builtin_correlation_rules() -> Vec<CorrelationRule> {
    let now = Utc::now();

    vec![
        // Brute Force Detection
        CorrelationRule {
            id: "corr-brute-force-login".to_string(),
            name: "Brute Force Login Attempt".to_string(),
            description: Some("Detects multiple failed login attempts from the same source".to_string()),
            rule_type: CorrelationRuleType::Threshold,
            conditions: CorrelationConditions {
                field_conditions: [
                    ("outcome".to_string(), FieldCondition::Exact("failure".to_string())),
                ].into_iter().collect(),
                ..Default::default()
            },
            time_window_secs: 60,
            threshold: Some(5),
            group_by: vec!["source_ip".to_string()],
            severity: SiemSeverity::Warning,
            enabled: true,
            mitre_tactics: vec!["credential_access".to_string()],
            mitre_techniques: vec!["T1110".to_string()],
            created_at: now,
            updated_at: now,
            created_by: None,
        },

        // Port Scan Detection
        CorrelationRule {
            id: "corr-port-scan".to_string(),
            name: "Port Scan Detection".to_string(),
            description: Some("Detects connection attempts to multiple ports from same source".to_string()),
            rule_type: CorrelationRuleType::UniqueValue,
            conditions: CorrelationConditions::default(),
            time_window_secs: 60,
            threshold: Some(10),
            group_by: vec!["source_ip".to_string(), "destination_port".to_string()],
            severity: SiemSeverity::Warning,
            enabled: true,
            mitre_tactics: vec!["reconnaissance".to_string()],
            mitre_techniques: vec!["T1046".to_string()],
            created_at: now,
            updated_at: now,
            created_by: None,
        },

        // Lateral Movement Detection (Login followed by process creation on different hosts)
        CorrelationRule {
            id: "corr-lateral-movement".to_string(),
            name: "Potential Lateral Movement".to_string(),
            description: Some("Detects login followed by suspicious activity on new host".to_string()),
            rule_type: CorrelationRuleType::Sequence,
            conditions: CorrelationConditions {
                sequence: vec![
                    SequenceStep {
                        name: "login".to_string(),
                        pattern: EventPattern {
                            name: "login_success".to_string(),
                            description: Some("Successful login".to_string()),
                            conditions: [
                                ("category".to_string(), FieldCondition::Exact("authentication".to_string())),
                                ("outcome".to_string(), FieldCondition::Exact("success".to_string())),
                            ].into_iter().collect(),
                            required: true,
                        },
                        max_span: None,
                        min_span: None,
                    },
                    SequenceStep {
                        name: "process".to_string(),
                        pattern: EventPattern {
                            name: "process_creation".to_string(),
                            description: Some("Process creation".to_string()),
                            conditions: [
                                ("category".to_string(), FieldCondition::Exact("process_creation".to_string())),
                            ].into_iter().collect(),
                            required: true,
                        },
                        max_span: Some(300),
                        min_span: None,
                    },
                ],
                ..Default::default()
            },
            time_window_secs: 300,
            threshold: None,
            group_by: vec!["user".to_string()],
            severity: SiemSeverity::Error,
            enabled: true,
            mitre_tactics: vec!["lateral_movement".to_string()],
            mitre_techniques: vec!["T1021".to_string()],
            created_at: now,
            updated_at: now,
            created_by: None,
        },

        // Data Exfiltration Detection (Large outbound transfers)
        CorrelationRule {
            id: "corr-data-exfil".to_string(),
            name: "Potential Data Exfiltration".to_string(),
            description: Some("Detects spike in outbound network traffic".to_string()),
            rule_type: CorrelationRuleType::Spike,
            conditions: CorrelationConditions {
                field_conditions: [
                    ("category".to_string(), FieldCondition::Exact("network".to_string())),
                ].into_iter().collect(),
                ..Default::default()
            },
            time_window_secs: 300,
            threshold: Some(100),
            group_by: vec!["source_ip".to_string()],
            severity: SiemSeverity::Critical,
            enabled: true,
            mitre_tactics: vec!["exfiltration".to_string()],
            mitre_techniques: vec!["T1041".to_string()],
            created_at: now,
            updated_at: now,
            created_by: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_threshold_rule() {
        let engine = CorrelationEngine::new();

        let rule = CorrelationRule {
            id: "test-threshold".to_string(),
            name: "Test Threshold Rule".to_string(),
            description: None,
            rule_type: CorrelationRuleType::Threshold,
            conditions: CorrelationConditions {
                field_conditions: [
                    ("outcome".to_string(), FieldCondition::Exact("failure".to_string())),
                ].into_iter().collect(),
                ..Default::default()
            },
            time_window_secs: 60,
            threshold: Some(3),
            group_by: vec!["source_ip".to_string()],
            severity: SiemSeverity::Warning,
            enabled: true,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
        };

        engine.add_rule(rule).await.unwrap();

        // Create test events
        for i in 0..4 {
            let mut entry = LogEntry::new(
                "test-source".to_string(),
                format!("Login failed attempt {}", i),
                "raw".to_string(),
            );
            entry.outcome = Some("failure".to_string());
            entry.source_ip = Some("192.168.1.100".parse().unwrap());

            let alerts = engine.process_event(&entry).await;
            if i >= 2 {
                // Should trigger alert after 3rd event
                assert!(!alerts.is_empty(), "Expected alert after {} events", i + 1);
            }
        }
    }

    #[tokio::test]
    async fn test_builtin_rules() {
        let rules = get_builtin_correlation_rules();
        assert!(rules.len() >= 4, "Should have at least 4 built-in rules");
    }
}
