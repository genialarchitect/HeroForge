//! False Positive Management
//!
//! This module provides:
//! - FP reporting workflow
//! - FP patterns and exceptions
//! - Tuning recommendations
//! - FP rate tracking per detection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a false positive report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FalsePositiveStatus {
    /// Newly reported, awaiting review
    Pending,
    /// Under investigation
    Investigating,
    /// Confirmed as false positive
    Confirmed,
    /// Rejected - was actually a true positive
    Rejected,
    /// Exception created and applied
    Resolved,
    /// Closed without action (duplicate, etc.)
    Closed,
}

impl Default for FalsePositiveStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for FalsePositiveStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Investigating => write!(f, "investigating"),
            Self::Confirmed => write!(f, "confirmed"),
            Self::Rejected => write!(f, "rejected"),
            Self::Resolved => write!(f, "resolved"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Type of tuning applied to reduce false positives
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuningType {
    /// Add exclusion pattern
    Exclusion,
    /// Modify threshold
    Threshold,
    /// Adjust aggregation
    Aggregation,
    /// Change time window
    TimeWindow,
    /// Add field filter
    FieldFilter,
    /// Modify severity
    Severity,
    /// Suppress for specific source
    SourceSuppression,
    /// Modify detection logic
    LogicModification,
    /// Other tuning type
    Other,
}

impl std::fmt::Display for TuningType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exclusion => write!(f, "exclusion"),
            Self::Threshold => write!(f, "threshold"),
            Self::Aggregation => write!(f, "aggregation"),
            Self::TimeWindow => write!(f, "time_window"),
            Self::FieldFilter => write!(f, "field_filter"),
            Self::Severity => write!(f, "severity"),
            Self::SourceSuppression => write!(f, "source_suppression"),
            Self::LogicModification => write!(f, "logic_modification"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// A pattern that identifies false positives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositivePattern {
    /// Unique pattern ID
    pub id: String,
    /// Detection ID this pattern applies to
    pub detection_id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: Option<String>,
    /// Field to match
    pub field: String,
    /// Match type (exact, contains, regex, cidr, etc.)
    pub match_type: PatternMatchType,
    /// Pattern value
    pub value: String,
    /// Whether this pattern is enabled
    pub enabled: bool,
    /// Number of times this pattern matched
    pub match_count: u64,
    /// When this pattern was created
    pub created_at: DateTime<Utc>,
    /// Who created this pattern
    pub created_by: String,
    /// When this pattern was last matched
    pub last_matched: Option<DateTime<Utc>>,
    /// Expiration date (optional)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Pattern matching type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternMatchType {
    /// Exact match
    Exact,
    /// Contains substring
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Regular expression
    Regex,
    /// CIDR network match
    Cidr,
    /// Wildcard match
    Wildcard,
    /// Not equal
    NotEqual,
}

impl PatternMatchType {
    /// Check if a value matches this pattern
    pub fn matches(&self, pattern: &str, value: &str) -> bool {
        match self {
            Self::Exact => value == pattern,
            Self::Contains => value.contains(pattern),
            Self::StartsWith => value.starts_with(pattern),
            Self::EndsWith => value.ends_with(pattern),
            Self::Regex => {
                regex::Regex::new(pattern)
                    .map(|re| re.is_match(value))
                    .unwrap_or(false)
            }
            Self::Cidr => {
                // Simple CIDR matching using manual parsing
                // Format: x.x.x.x/prefix
                if let Some((network_str, prefix_str)) = pattern.split_once('/') {
                    if let (Ok(network_ip), Ok(prefix)) = (
                        network_str.parse::<std::net::Ipv4Addr>(),
                        prefix_str.parse::<u8>(),
                    ) {
                        if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
                            if prefix <= 32 {
                                let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                                let network_bits = u32::from(network_ip) & mask;
                                let ip_bits = u32::from(ip) & mask;
                                return network_bits == ip_bits;
                            }
                        }
                    }
                }
                false
            }
            Self::Wildcard => {
                // Convert wildcard to regex
                let regex_pattern = pattern
                    .replace('.', "\\.")
                    .replace('*', ".*")
                    .replace('?', ".");
                regex::Regex::new(&format!("^{}$", regex_pattern))
                    .map(|re| re.is_match(value))
                    .unwrap_or(false)
            }
            Self::NotEqual => value != pattern,
        }
    }
}

/// A false positive report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositive {
    /// Unique FP report ID
    pub id: String,
    /// Detection ID that generated the alert
    pub detection_id: String,
    /// Original alert ID
    pub alert_id: String,
    /// Reason for false positive
    pub reason: String,
    /// Detailed explanation
    pub explanation: Option<String>,
    /// Evidence supporting the FP claim
    pub evidence: Option<String>,
    /// Pattern to exclude similar events
    pub pattern: Option<FalsePositivePattern>,
    /// Exception rule (in detection language format)
    pub exception_rule: Option<String>,
    /// Current status
    pub status: FalsePositiveStatus,
    /// Priority for review
    pub priority: FalsePositivePriority,
    /// Who reported this FP
    pub reported_by: String,
    /// When reported
    pub created_at: DateTime<Utc>,
    /// When last updated
    pub updated_at: DateTime<Utc>,
    /// Assigned analyst
    pub assigned_to: Option<String>,
    /// Resolution notes
    pub resolution_notes: Option<String>,
    /// Resolved by
    pub resolved_by: Option<String>,
    /// Resolved at
    pub resolved_at: Option<DateTime<Utc>>,
    /// Original alert data (JSON)
    pub alert_data: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

/// Priority for FP review
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FalsePositivePriority {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for FalsePositivePriority {
    fn default() -> Self {
        Self::Medium
    }
}

/// A tuning recommendation to reduce false positives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningRecommendation {
    /// Unique recommendation ID
    pub id: String,
    /// Detection ID this applies to
    pub detection_id: String,
    /// Type of tuning
    pub tuning_type: TuningType,
    /// Description of the recommendation
    pub description: String,
    /// Current value (before tuning)
    pub original_value: String,
    /// Recommended new value
    pub recommended_value: String,
    /// Expected FP reduction percentage
    pub expected_reduction: f64,
    /// Confidence in this recommendation (0-1)
    pub confidence: f64,
    /// Supporting data/analysis
    pub analysis: Option<String>,
    /// Number of FPs this would address
    pub fp_count: u32,
    /// Impact on true positive rate
    pub tp_impact: Option<String>,
    /// Whether this has been applied
    pub applied: bool,
    /// When applied
    pub applied_at: Option<DateTime<Utc>>,
    /// Applied by
    pub applied_by: Option<String>,
    /// Generated at
    pub created_at: DateTime<Utc>,
}

/// Record of tuning applied to a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionTuning {
    /// Unique tuning record ID
    pub id: String,
    /// Detection ID
    pub detection_id: String,
    /// Type of tuning
    pub tuning_type: TuningType,
    /// Original value before tuning
    pub original_value: String,
    /// New value after tuning
    pub new_value: String,
    /// Reason for tuning
    pub reason: String,
    /// Related FP IDs
    pub related_fp_ids: Vec<String>,
    /// When applied
    pub applied_at: DateTime<Utc>,
    /// Who applied it
    pub applied_by: String,
    /// Whether this tuning is still active
    pub active: bool,
    /// Rollback timestamp (if rolled back)
    pub rolled_back_at: Option<DateTime<Utc>>,
}

/// FP rate statistics for a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveStats {
    /// Detection ID
    pub detection_id: String,
    /// Total alerts generated
    pub total_alerts: u64,
    /// Confirmed false positives
    pub false_positives: u64,
    /// Confirmed true positives
    pub true_positives: u64,
    /// Pending review
    pub pending_review: u64,
    /// FP rate (0-1)
    pub fp_rate: f64,
    /// Trend over last 30 days
    pub trend: FpTrend,
    /// Average time to resolution (seconds)
    pub avg_resolution_time: Option<f64>,
    /// Top FP patterns
    pub top_patterns: Vec<PatternStats>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
}

/// FP rate trend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FpTrend {
    Improving,
    Stable,
    Worsening,
    Unknown,
}

/// Statistics for a FP pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStats {
    /// Pattern description
    pub pattern: String,
    /// Field matched
    pub field: String,
    /// Count of matches
    pub count: u64,
    /// Percentage of total FPs
    pub percentage: f64,
}

/// FP analyzer for generating recommendations
pub struct FalsePositiveAnalyzer;

impl FalsePositiveAnalyzer {
    /// Analyze false positives and generate tuning recommendations
    pub fn analyze(fps: &[FalsePositive]) -> Vec<TuningRecommendation> {
        let mut recommendations = Vec::new();
        let mut pattern_counts: HashMap<(String, String), Vec<&FalsePositive>> = HashMap::new();

        // Group FPs by detection and pattern
        for fp in fps.iter().filter(|f| f.status == FalsePositiveStatus::Confirmed) {
            if let Some(ref pattern) = fp.pattern {
                let key = (fp.detection_id.clone(), pattern.field.clone());
                pattern_counts.entry(key).or_default().push(fp);
            }
        }

        // Generate recommendations for patterns with multiple FPs
        for ((detection_id, field), fps) in pattern_counts {
            if fps.len() >= 3 {
                // Extract common values
                let values: Vec<String> = fps.iter()
                    .filter_map(|fp| fp.pattern.as_ref().map(|p| p.value.clone()))
                    .collect();

                let common_prefix = find_common_prefix(&values);
                let common_suffix = find_common_suffix(&values);

                if !common_prefix.is_empty() || !common_suffix.is_empty() {
                    let pattern_suggestion = if !common_prefix.is_empty() {
                        format!("{}*", common_prefix)
                    } else {
                        format!("*{}", common_suffix)
                    };

                    recommendations.push(TuningRecommendation {
                        id: uuid::Uuid::new_v4().to_string(),
                        detection_id: detection_id.clone(),
                        tuning_type: TuningType::Exclusion,
                        description: format!(
                            "Add exclusion pattern for field '{}' matching '{}'",
                            field, pattern_suggestion
                        ),
                        original_value: "No exclusion".to_string(),
                        recommended_value: format!("Exclude where {} matches '{}'", field, pattern_suggestion),
                        expected_reduction: (fps.len() as f64 / fps.len() as f64).min(0.8),
                        confidence: 0.7,
                        analysis: Some(format!("Based on {} confirmed false positives", fps.len())),
                        fp_count: fps.len() as u32,
                        tp_impact: Some("Minimal - patterns are specific".to_string()),
                        applied: false,
                        applied_at: None,
                        applied_by: None,
                        created_at: Utc::now(),
                    });
                }
            }
        }

        // Analyze threshold-related FPs
        let threshold_fps: Vec<_> = fps.iter()
            .filter(|f| f.status == FalsePositiveStatus::Confirmed)
            .filter(|f| f.reason.to_lowercase().contains("threshold") ||
                       f.reason.to_lowercase().contains("count"))
            .collect();

        if threshold_fps.len() >= 2 {
            let detection_ids: std::collections::HashSet<_> = threshold_fps.iter()
                .map(|f| &f.detection_id)
                .collect();

            for detection_id in detection_ids {
                let count = threshold_fps.iter()
                    .filter(|f| &f.detection_id == detection_id)
                    .count();

                if count >= 2 {
                    recommendations.push(TuningRecommendation {
                        id: uuid::Uuid::new_v4().to_string(),
                        detection_id: detection_id.clone(),
                        tuning_type: TuningType::Threshold,
                        description: "Consider increasing the alert threshold".to_string(),
                        original_value: "Current threshold".to_string(),
                        recommended_value: "Increase by 20-50%".to_string(),
                        expected_reduction: 0.4,
                        confidence: 0.6,
                        analysis: Some(format!("{} threshold-related FPs identified", count)),
                        fp_count: count as u32,
                        tp_impact: Some("May delay detection of slow attacks".to_string()),
                        applied: false,
                        applied_at: None,
                        applied_by: None,
                        created_at: Utc::now(),
                    });
                }
            }
        }

        recommendations
    }

    /// Calculate FP statistics for a detection
    pub fn calculate_stats(
        detection_id: &str,
        fps: &[FalsePositive],
        total_alerts: u64,
    ) -> FalsePositiveStats {
        let detection_fps: Vec<_> = fps.iter()
            .filter(|f| f.detection_id == detection_id)
            .collect();

        let confirmed = detection_fps.iter()
            .filter(|f| f.status == FalsePositiveStatus::Confirmed ||
                       f.status == FalsePositiveStatus::Resolved)
            .count() as u64;

        let rejected = detection_fps.iter()
            .filter(|f| f.status == FalsePositiveStatus::Rejected)
            .count() as u64;

        let pending = detection_fps.iter()
            .filter(|f| f.status == FalsePositiveStatus::Pending ||
                       f.status == FalsePositiveStatus::Investigating)
            .count() as u64;

        let fp_rate = if total_alerts > 0 {
            confirmed as f64 / total_alerts as f64
        } else {
            0.0
        };

        // Calculate average resolution time
        let resolved: Vec<_> = detection_fps.iter()
            .filter(|f| f.resolved_at.is_some())
            .collect();

        let avg_resolution = if !resolved.is_empty() {
            let total_time: f64 = resolved.iter()
                .filter_map(|f| {
                    f.resolved_at.map(|r| {
                        (r - f.created_at).num_seconds() as f64
                    })
                })
                .sum();
            Some(total_time / resolved.len() as f64)
        } else {
            None
        };

        // Calculate pattern statistics
        let mut pattern_stats: HashMap<String, (String, u64)> = HashMap::new();
        for fp in detection_fps.iter().filter(|f| f.pattern.is_some()) {
            if let Some(ref pattern) = fp.pattern {
                let key = format!("{}:{}", pattern.field, pattern.value);
                let entry = pattern_stats.entry(key).or_insert((pattern.field.clone(), 0));
                entry.1 += 1;
            }
        }

        let total_patterns = pattern_stats.values().map(|(_, c)| c).sum::<u64>();
        let mut top_patterns: Vec<_> = pattern_stats.into_iter()
            .map(|(pattern, (field, count))| PatternStats {
                pattern,
                field,
                count,
                percentage: if total_patterns > 0 {
                    count as f64 / total_patterns as f64 * 100.0
                } else {
                    0.0
                },
            })
            .collect();
        top_patterns.sort_by(|a, b| b.count.cmp(&a.count));
        top_patterns.truncate(5);

        FalsePositiveStats {
            detection_id: detection_id.to_string(),
            total_alerts,
            false_positives: confirmed,
            true_positives: rejected,
            pending_review: pending,
            fp_rate,
            trend: FpTrend::Unknown, // Would need historical data
            avg_resolution_time: avg_resolution,
            top_patterns,
            updated_at: Utc::now(),
        }
    }

    /// Suggest pattern based on FP data
    pub fn suggest_pattern(fp: &FalsePositive) -> Option<FalsePositivePattern> {
        // Try to extract pattern from alert data
        if let Some(ref alert_data) = fp.alert_data {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(alert_data) {
                // Look for common FP-prone fields
                let fp_fields = ["user", "hostname", "source_ip", "process_name", "command_line"];

                for field in fp_fields {
                    if let Some(value) = data.get(field) {
                        if let Some(value_str) = value.as_str() {
                            return Some(FalsePositivePattern {
                                id: uuid::Uuid::new_v4().to_string(),
                                detection_id: fp.detection_id.clone(),
                                name: format!("Auto-suggested pattern for {}", field),
                                description: Some(format!(
                                    "Suggested based on FP report: {}",
                                    fp.reason
                                )),
                                field: field.to_string(),
                                match_type: PatternMatchType::Exact,
                                value: value_str.to_string(),
                                enabled: false, // Requires manual review
                                match_count: 0,
                                created_at: Utc::now(),
                                created_by: "system".to_string(),
                                last_matched: None,
                                expires_at: None,
                            });
                        }
                    }
                }
            }
        }
        None
    }
}

/// Find common prefix among strings
fn find_common_prefix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }

    let first = &strings[0];
    let mut prefix_len = 0;

    for (i, c) in first.chars().enumerate() {
        if strings.iter().all(|s| s.chars().nth(i) == Some(c)) {
            prefix_len = i + 1;
        } else {
            break;
        }
    }

    first[..prefix_len].to_string()
}

/// Find common suffix among strings
fn find_common_suffix(strings: &[String]) -> String {
    if strings.is_empty() {
        return String::new();
    }

    let reversed: Vec<String> = strings.iter()
        .map(|s| s.chars().rev().collect())
        .collect();

    let common = find_common_prefix(&reversed);
    common.chars().rev().collect()
}

/// Workflow manager for FP handling
pub struct FalsePositiveWorkflow;

impl FalsePositiveWorkflow {
    /// Check if status transition is valid
    pub fn validate_transition(from: FalsePositiveStatus, to: FalsePositiveStatus) -> bool {
        match (from, to) {
            // Pending can go to investigating, confirmed, rejected, or closed
            (FalsePositiveStatus::Pending, FalsePositiveStatus::Investigating) => true,
            (FalsePositiveStatus::Pending, FalsePositiveStatus::Confirmed) => true,
            (FalsePositiveStatus::Pending, FalsePositiveStatus::Rejected) => true,
            (FalsePositiveStatus::Pending, FalsePositiveStatus::Closed) => true,

            // Investigating can go to confirmed, rejected, or closed
            (FalsePositiveStatus::Investigating, FalsePositiveStatus::Confirmed) => true,
            (FalsePositiveStatus::Investigating, FalsePositiveStatus::Rejected) => true,
            (FalsePositiveStatus::Investigating, FalsePositiveStatus::Closed) => true,

            // Confirmed can go to resolved
            (FalsePositiveStatus::Confirmed, FalsePositiveStatus::Resolved) => true,

            // Rejected can be reopened (back to investigating)
            (FalsePositiveStatus::Rejected, FalsePositiveStatus::Investigating) => true,

            // Resolved can be reopened (back to confirmed)
            (FalsePositiveStatus::Resolved, FalsePositiveStatus::Confirmed) => true,

            // Closed can be reopened
            (FalsePositiveStatus::Closed, FalsePositiveStatus::Pending) => true,

            _ => false,
        }
    }

    /// Get available next statuses
    pub fn get_next_statuses(current: FalsePositiveStatus) -> Vec<FalsePositiveStatus> {
        match current {
            FalsePositiveStatus::Pending => vec![
                FalsePositiveStatus::Investigating,
                FalsePositiveStatus::Confirmed,
                FalsePositiveStatus::Rejected,
                FalsePositiveStatus::Closed,
            ],
            FalsePositiveStatus::Investigating => vec![
                FalsePositiveStatus::Confirmed,
                FalsePositiveStatus::Rejected,
                FalsePositiveStatus::Closed,
            ],
            FalsePositiveStatus::Confirmed => vec![
                FalsePositiveStatus::Resolved,
            ],
            FalsePositiveStatus::Rejected => vec![
                FalsePositiveStatus::Investigating,
            ],
            FalsePositiveStatus::Resolved => vec![
                FalsePositiveStatus::Confirmed,
            ],
            FalsePositiveStatus::Closed => vec![
                FalsePositiveStatus::Pending,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(PatternMatchType::Exact.matches("test", "test"));
        assert!(!PatternMatchType::Exact.matches("test", "Test"));

        assert!(PatternMatchType::Contains.matches("est", "testing"));
        assert!(!PatternMatchType::Contains.matches("xyz", "testing"));

        assert!(PatternMatchType::StartsWith.matches("test", "testing"));
        assert!(PatternMatchType::EndsWith.matches("ing", "testing"));

        assert!(PatternMatchType::Regex.matches(r"\d+", "123"));
        assert!(!PatternMatchType::Regex.matches(r"\d+", "abc"));

        assert!(PatternMatchType::Wildcard.matches("test*", "testing"));
        assert!(PatternMatchType::Wildcard.matches("*.exe", "cmd.exe"));

        assert!(PatternMatchType::Cidr.matches("192.168.1.0/24", "192.168.1.100"));
        assert!(!PatternMatchType::Cidr.matches("192.168.1.0/24", "192.168.2.1"));
    }

    #[test]
    fn test_status_transitions() {
        assert!(FalsePositiveWorkflow::validate_transition(
            FalsePositiveStatus::Pending,
            FalsePositiveStatus::Investigating
        ));

        assert!(FalsePositiveWorkflow::validate_transition(
            FalsePositiveStatus::Confirmed,
            FalsePositiveStatus::Resolved
        ));

        assert!(!FalsePositiveWorkflow::validate_transition(
            FalsePositiveStatus::Pending,
            FalsePositiveStatus::Resolved
        ));
    }

    #[test]
    fn test_common_prefix() {
        let strings = vec![
            "admin_user1".to_string(),
            "admin_user2".to_string(),
            "admin_user3".to_string(),
        ];
        assert_eq!(find_common_prefix(&strings), "admin_user");

        let no_common = vec!["abc".to_string(), "xyz".to_string()];
        assert_eq!(find_common_prefix(&no_common), "");
    }

    #[test]
    fn test_common_suffix() {
        let strings = vec![
            "file1.exe".to_string(),
            "file2.exe".to_string(),
            "file3.exe".to_string(),
        ];
        assert_eq!(find_common_suffix(&strings), ".exe");
    }

    #[test]
    fn test_fp_stats_calculation() {
        let now = Utc::now();
        let fps = vec![
            FalsePositive {
                id: "FP-001".to_string(),
                detection_id: "DET-001".to_string(),
                alert_id: "A001".to_string(),
                reason: "Benign activity".to_string(),
                explanation: None,
                evidence: None,
                pattern: None,
                exception_rule: None,
                status: FalsePositiveStatus::Confirmed,
                priority: FalsePositivePriority::Medium,
                reported_by: "analyst".to_string(),
                created_at: now - chrono::Duration::hours(2),
                updated_at: now,
                assigned_to: None,
                resolution_notes: None,
                resolved_by: Some("analyst".to_string()),
                resolved_at: Some(now),
                alert_data: None,
                tags: Vec::new(),
            },
            FalsePositive {
                id: "FP-002".to_string(),
                detection_id: "DET-001".to_string(),
                alert_id: "A002".to_string(),
                reason: "Known good".to_string(),
                explanation: None,
                evidence: None,
                pattern: None,
                exception_rule: None,
                status: FalsePositiveStatus::Pending,
                priority: FalsePositivePriority::Low,
                reported_by: "analyst".to_string(),
                created_at: now,
                updated_at: now,
                assigned_to: None,
                resolution_notes: None,
                resolved_by: None,
                resolved_at: None,
                alert_data: None,
                tags: Vec::new(),
            },
        ];

        let stats = FalsePositiveAnalyzer::calculate_stats("DET-001", &fps, 100);

        assert_eq!(stats.false_positives, 1);
        assert_eq!(stats.pending_review, 1);
        assert!((stats.fp_rate - 0.01).abs() < 0.001);
    }
}
