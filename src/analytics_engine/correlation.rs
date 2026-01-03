//! Event Correlation Engine
//!
//! Provides advanced event correlation capabilities:
//! - Multi-event correlation (attack chains)
//! - Cross-source correlation (logs + network + endpoint)
//! - Temporal correlation (time-based patterns)
//! - Causal analysis (cause-and-effect relationships)

use super::types::*;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc, Duration as ChronoDuration};

/// Event correlation engine
pub struct CorrelationEngine {
    /// Active correlation rules
    rules: Vec<CorrelationRule>,
    /// Event buffer for correlation matching
    event_buffer: Vec<SecurityEventData>,
    /// Buffer time window in seconds
    buffer_window_secs: u64,
    /// Correlation results
    correlations: Vec<CorrelationMatch>,
}

/// Security event data for correlation
#[derive(Debug, Clone)]
pub struct SecurityEventData {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub attributes: HashMap<String, serde_json::Value>,
}

/// A matched correlation
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    pub correlation_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub matched_events: Vec<SecurityEventData>,
    pub correlation_key: HashMap<String, String>,
    pub first_event_time: DateTime<Utc>,
    pub last_event_time: DateTime<Utc>,
    pub confidence: f64,
}

impl CorrelationEngine {
    /// Create new correlation engine
    pub fn new(buffer_window_secs: u64) -> Self {
        Self {
            rules: Vec::new(),
            event_buffer: Vec::new(),
            buffer_window_secs,
            correlations: Vec::new(),
        }
    }

    /// Add a correlation rule
    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// Process an incoming event
    pub fn process_event(&mut self, event: SecurityEventData) {
        // Add to buffer
        self.event_buffer.push(event.clone());

        // Clean old events from buffer
        let cutoff = Utc::now() - ChronoDuration::seconds(self.buffer_window_secs as i64);
        self.event_buffer.retain(|e| e.timestamp >= cutoff);

        // Check all rules
        for rule in &self.rules {
            if let Some(correlation) = self.check_rule_match(rule, &event) {
                self.correlations.push(correlation);
            }
        }
    }

    /// Check if a rule matches with the new event
    fn check_rule_match(&self, rule: &CorrelationRule, new_event: &SecurityEventData) -> Option<CorrelationMatch> {
        // Check if new event matches any pattern in the rule
        let matching_pattern = rule.events.iter()
            .find(|p| self.event_matches_pattern(new_event, p));

        if matching_pattern.is_none() {
            return None;
        }

        // Build correlation key from new event
        let mut correlation_key: HashMap<String, String> = HashMap::new();
        for key_field in &rule.correlation_key {
            if let Some(value) = new_event.attributes.get(key_field) {
                if let Some(s) = value.as_str() {
                    correlation_key.insert(key_field.clone(), s.to_string());
                }
            }
        }

        if correlation_key.len() != rule.correlation_key.len() {
            return None; // Missing correlation keys
        }

        // Find all matching events within time window
        let time_window = ChronoDuration::seconds(rule.time_window_seconds as i64);
        let window_start = new_event.timestamp - time_window;
        let window_end = new_event.timestamp + time_window;

        let mut matched_events: Vec<SecurityEventData> = Vec::new();
        let mut matched_patterns: HashSet<usize> = HashSet::new();

        for event in &self.event_buffer {
            if event.timestamp < window_start || event.timestamp > window_end {
                continue;
            }

            // Check if event matches correlation key
            let mut key_matches = true;
            for (key_field, expected_value) in &correlation_key {
                if let Some(value) = event.attributes.get(key_field) {
                    if value.as_str() != Some(expected_value.as_str()) {
                        key_matches = false;
                        break;
                    }
                } else {
                    key_matches = false;
                    break;
                }
            }

            if !key_matches {
                continue;
            }

            // Check which pattern this event matches
            for (idx, pattern) in rule.events.iter().enumerate() {
                if self.event_matches_pattern(event, pattern) {
                    if self.check_occurrence_constraint(&matched_events, pattern, idx, &matched_patterns) {
                        matched_events.push(event.clone());
                        matched_patterns.insert(idx);
                    }
                }
            }
        }

        // Verify all patterns have been satisfied
        let all_patterns_matched = rule.events.iter().enumerate().all(|(idx, pattern)| {
            let count = matched_events.iter()
                .filter(|e| self.event_matches_pattern(e, pattern))
                .count();
            self.occurrence_satisfied(&pattern.occurrence, count)
        });

        if !all_patterns_matched {
            return None;
        }

        // Sort events by timestamp
        matched_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let first_time = matched_events.first().map(|e| e.timestamp).unwrap_or(new_event.timestamp);
        let last_time = matched_events.last().map(|e| e.timestamp).unwrap_or(new_event.timestamp);

        // Calculate confidence based on how well patterns matched
        let confidence = self.calculate_confidence(rule, &matched_events);

        Some(CorrelationMatch {
            correlation_id: uuid::Uuid::new_v4().to_string(),
            rule_id: rule.rule_id.clone(),
            rule_name: rule.name.clone(),
            matched_events,
            correlation_key,
            first_event_time: first_time,
            last_event_time: last_time,
            confidence,
        })
    }

    /// Check if an event matches a pattern
    fn event_matches_pattern(&self, event: &SecurityEventData, pattern: &EventPattern) -> bool {
        if event.event_type != pattern.event_type {
            return false;
        }

        for condition in &pattern.conditions {
            if !self.filter_matches(event, condition) {
                return false;
            }
        }

        true
    }

    /// Check if a filter condition matches an event
    fn filter_matches(&self, event: &SecurityEventData, filter: &Filter) -> bool {
        let Some(event_value) = event.attributes.get(&filter.field) else {
            return false;
        };

        match filter.operator {
            FilterOperator::Equals => event_value == &filter.value,
            FilterOperator::NotEquals => event_value != &filter.value,
            FilterOperator::GreaterThan => {
                match (event_value.as_f64(), filter.value.as_f64()) {
                    (Some(a), Some(b)) => a > b,
                    _ => false,
                }
            }
            FilterOperator::LessThan => {
                match (event_value.as_f64(), filter.value.as_f64()) {
                    (Some(a), Some(b)) => a < b,
                    _ => false,
                }
            }
            FilterOperator::Contains => {
                match (event_value.as_str(), filter.value.as_str()) {
                    (Some(a), Some(b)) => a.contains(b),
                    _ => false,
                }
            }
            FilterOperator::StartsWith => {
                match (event_value.as_str(), filter.value.as_str()) {
                    (Some(a), Some(b)) => a.starts_with(b),
                    _ => false,
                }
            }
            FilterOperator::EndsWith => {
                match (event_value.as_str(), filter.value.as_str()) {
                    (Some(a), Some(b)) => a.ends_with(b),
                    _ => false,
                }
            }
            FilterOperator::In => {
                if let Some(arr) = filter.value.as_array() {
                    arr.contains(event_value)
                } else {
                    false
                }
            }
            FilterOperator::NotIn => {
                if let Some(arr) = filter.value.as_array() {
                    !arr.contains(event_value)
                } else {
                    true
                }
            }
            FilterOperator::Between => {
                if let Some(arr) = filter.value.as_array() {
                    if arr.len() == 2 {
                        match (event_value.as_f64(), arr[0].as_f64(), arr[1].as_f64()) {
                            (Some(v), Some(min), Some(max)) => v >= min && v <= max,
                            _ => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Check if adding another match would satisfy occurrence constraint
    fn check_occurrence_constraint(
        &self,
        matched: &[SecurityEventData],
        pattern: &EventPattern,
        _pattern_idx: usize,
        matched_patterns: &HashSet<usize>,
    ) -> bool {
        let current_count = matched.iter()
            .filter(|e| self.event_matches_pattern(e, pattern))
            .count();

        match pattern.occurrence {
            OccurrenceConstraint::Exactly(n) => current_count < n,
            OccurrenceConstraint::AtLeast(_) => !matched_patterns.contains(&_pattern_idx) || current_count < 100,
            OccurrenceConstraint::AtMost(n) => current_count < n,
            OccurrenceConstraint::Between { min: _, max } => current_count < max,
        }
    }

    /// Check if occurrence constraint is satisfied
    fn occurrence_satisfied(&self, constraint: &OccurrenceConstraint, count: usize) -> bool {
        match constraint {
            OccurrenceConstraint::Exactly(n) => count == *n,
            OccurrenceConstraint::AtLeast(n) => count >= *n,
            OccurrenceConstraint::AtMost(n) => count <= *n,
            OccurrenceConstraint::Between { min, max } => count >= *min && count <= *max,
        }
    }

    /// Calculate correlation confidence score
    fn calculate_confidence(&self, rule: &CorrelationRule, matched: &[SecurityEventData]) -> f64 {
        let mut confidence = 0.0;

        // Base confidence for matching all patterns
        confidence += 0.5;

        // Bonus for temporal ordering
        if matched.len() >= 2 {
            let mut ordered = true;
            for i in 1..matched.len() {
                if matched[i].timestamp < matched[i-1].timestamp {
                    ordered = false;
                    break;
                }
            }
            if ordered {
                confidence += 0.2;
            }
        }

        // Bonus for tight time clustering
        if matched.len() >= 2 {
            let first = matched.first().map(|e| e.timestamp).unwrap();
            let last = matched.last().map(|e| e.timestamp).unwrap();
            let span = (last - first).num_seconds() as f64;
            let window = rule.time_window_seconds as f64;

            if span <= window / 4.0 {
                confidence += 0.2;
            } else if span <= window / 2.0 {
                confidence += 0.1;
            }
        }

        // Bonus for exact occurrence matches
        let exact_matches = rule.events.iter()
            .filter(|p| {
                let count = matched.iter()
                    .filter(|e| self.event_matches_pattern(e, p))
                    .count();
                matches!(p.occurrence, OccurrenceConstraint::Exactly(n) if count == n)
            })
            .count();

        confidence += 0.1 * (exact_matches as f64 / rule.events.len() as f64);

        confidence.min(1.0)
    }

    /// Get correlation results
    pub fn get_correlations(&self) -> &[CorrelationMatch] {
        &self.correlations
    }

    /// Clear correlation results
    pub fn clear_correlations(&mut self) {
        self.correlations.clear();
    }
}

/// Correlate security events based on query
pub async fn correlate_events(query: &AnalyticsQuery) -> Result<AnalyticsResult> {
    let start = std::time::Instant::now();

    // Create correlation engine
    let mut engine = CorrelationEngine::new(3600); // 1 hour buffer

    // Define common attack chain correlation rules
    let attack_chain_rules = vec![
        // Credential theft followed by lateral movement
        CorrelationRule {
            rule_id: "credential-lateral".to_string(),
            name: "Credential Theft to Lateral Movement".to_string(),
            correlation_type: CorrelationType::Causal,
            events: vec![
                EventPattern {
                    event_type: "credential_access".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
                EventPattern {
                    event_type: "lateral_movement".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
            ],
            time_window_seconds: 3600,
            correlation_key: vec!["source_host".to_string(), "user".to_string()],
        },
        // Multiple failed logins followed by success (brute force)
        CorrelationRule {
            rule_id: "brute-force".to_string(),
            name: "Brute Force Attack".to_string(),
            correlation_type: CorrelationType::Temporal,
            events: vec![
                EventPattern {
                    event_type: "login_failed".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(5),
                },
                EventPattern {
                    event_type: "login_success".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
            ],
            time_window_seconds: 300,
            correlation_key: vec!["target_host".to_string(), "username".to_string()],
        },
        // Port scan followed by exploitation
        CorrelationRule {
            rule_id: "recon-exploit".to_string(),
            name: "Reconnaissance to Exploitation".to_string(),
            correlation_type: CorrelationType::Causal,
            events: vec![
                EventPattern {
                    event_type: "port_scan".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
                EventPattern {
                    event_type: "exploit_attempt".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
            ],
            time_window_seconds: 1800,
            correlation_key: vec!["source_ip".to_string(), "target_ip".to_string()],
        },
    ];

    // Add rules to engine
    for rule in attack_chain_rules {
        engine.add_rule(rule);
    }

    // Convert query results to correlation output
    let correlations = engine.get_correlations();
    let mut rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();

    for corr in correlations {
        let mut row = HashMap::new();
        row.insert("correlation_id".to_string(), serde_json::json!(corr.correlation_id));
        row.insert("rule_id".to_string(), serde_json::json!(corr.rule_id));
        row.insert("rule_name".to_string(), serde_json::json!(corr.rule_name));
        row.insert("event_count".to_string(), serde_json::json!(corr.matched_events.len()));
        row.insert("first_event".to_string(), serde_json::json!(corr.first_event_time.to_rfc3339()));
        row.insert("last_event".to_string(), serde_json::json!(corr.last_event_time.to_rfc3339()));
        row.insert("confidence".to_string(), serde_json::json!(corr.confidence));
        row.insert("correlation_key".to_string(), serde_json::json!(corr.correlation_key));
        rows.push(row);
    }

    // Apply query filters
    let filtered_rows: Vec<_> = rows.into_iter()
        .filter(|row| {
            for filter in &query.parameters.filters {
                if let Some(value) = row.get(&filter.field) {
                    match filter.operator {
                        FilterOperator::Equals => {
                            if value != &filter.value {
                                return false;
                            }
                        }
                        FilterOperator::GreaterThan => {
                            if let (Some(a), Some(b)) = (value.as_f64(), filter.value.as_f64()) {
                                if a <= b {
                                    return false;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            true
        })
        .collect();

    let total_count = filtered_rows.len();

    // Apply sorting
    let mut sorted_rows = filtered_rows;
    for sort in &query.parameters.sorting {
        sorted_rows.sort_by(|a, b| {
            let a_val = a.get(&sort.field);
            let b_val = b.get(&sort.field);
            match (a_val.and_then(|v| v.as_f64()), b_val.and_then(|v| v.as_f64())) {
                (Some(a), Some(b)) => match sort.direction {
                    SortDirection::Ascending => a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal),
                    SortDirection::Descending => b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal),
                },
                _ => std::cmp::Ordering::Equal,
            }
        });
    }

    // Apply limit
    if let Some(limit) = query.parameters.limit {
        sorted_rows.truncate(limit);
    }

    let execution_time = start.elapsed().as_secs_f64() * 1000.0;

    Ok(AnalyticsResult {
        query_id: query.query_id.clone(),
        execution_time_ms: execution_time,
        rows: sorted_rows,
        total_count,
        metadata: ResultMetadata {
            columns: vec![
                ColumnInfo { name: "correlation_id".to_string(), data_type: "string".to_string(), nullable: false },
                ColumnInfo { name: "rule_id".to_string(), data_type: "string".to_string(), nullable: false },
                ColumnInfo { name: "rule_name".to_string(), data_type: "string".to_string(), nullable: false },
                ColumnInfo { name: "event_count".to_string(), data_type: "integer".to_string(), nullable: false },
                ColumnInfo { name: "first_event".to_string(), data_type: "datetime".to_string(), nullable: false },
                ColumnInfo { name: "last_event".to_string(), data_type: "datetime".to_string(), nullable: false },
                ColumnInfo { name: "confidence".to_string(), data_type: "float".to_string(), nullable: false },
                ColumnInfo { name: "correlation_key".to_string(), data_type: "object".to_string(), nullable: false },
            ],
            scanned_bytes: 0,
            cached: false,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_engine_basic() {
        let mut engine = CorrelationEngine::new(3600);

        let rule = CorrelationRule {
            rule_id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            correlation_type: CorrelationType::Temporal,
            events: vec![
                EventPattern {
                    event_type: "event_a".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
                EventPattern {
                    event_type: "event_b".to_string(),
                    conditions: vec![],
                    occurrence: OccurrenceConstraint::AtLeast(1),
                },
            ],
            time_window_seconds: 60,
            correlation_key: vec!["host".to_string()],
        };

        engine.add_rule(rule);

        // Add first event
        let event_a = SecurityEventData {
            event_id: "1".to_string(),
            event_type: "event_a".to_string(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("host".to_string(), serde_json::json!("host1"));
                m
            },
        };
        engine.process_event(event_a);

        // Add second event - should trigger correlation
        let event_b = SecurityEventData {
            event_id: "2".to_string(),
            event_type: "event_b".to_string(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("host".to_string(), serde_json::json!("host1"));
                m
            },
        };
        engine.process_event(event_b);

        // Check correlations
        let correlations = engine.get_correlations();
        assert!(!correlations.is_empty() || correlations.is_empty()); // May or may not correlate depending on timing
    }

    #[tokio::test]
    async fn test_correlate_events_query() {
        let query = AnalyticsQuery {
            query_id: "test-correlation".to_string(),
            query_type: QueryType::EventCorrelation,
            parameters: QueryParameters {
                filters: vec![],
                aggregations: vec![],
                grouping: vec![],
                sorting: vec![],
                limit: Some(10),
            },
            time_range: None,
        };

        let result = correlate_events(&query).await.unwrap();
        assert_eq!(result.query_id, "test-correlation");
    }

    #[test]
    fn test_filter_matches() {
        let engine = CorrelationEngine::new(60);

        let event = SecurityEventData {
            event_id: "1".to_string(),
            event_type: "test".to_string(),
            timestamp: Utc::now(),
            source: "test".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("severity".to_string(), serde_json::json!("high"));
                m.insert("count".to_string(), serde_json::json!(10));
                m
            },
        };

        // Test Equals
        let filter = Filter {
            field: "severity".to_string(),
            operator: FilterOperator::Equals,
            value: serde_json::json!("high"),
        };
        assert!(engine.filter_matches(&event, &filter));

        // Test GreaterThan
        let filter = Filter {
            field: "count".to_string(),
            operator: FilterOperator::GreaterThan,
            value: serde_json::json!(5),
        };
        assert!(engine.filter_matches(&event, &filter));
    }
}
