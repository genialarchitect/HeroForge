//! YARA Rule Effectiveness Scoring and Tracking
//!
//! Tracks and calculates effectiveness scores for YARA rules based on:
//! - Match statistics (total matches, unique files)
//! - False positive rates
//! - True positive verifications
//! - Detection quality metrics
//! - Performance characteristics

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Types
// ============================================================================

/// Effectiveness score for a YARA rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEffectivenessScore {
    /// Rule ID
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Overall effectiveness score (0.0 - 100.0)
    pub score: f64,
    /// Detection accuracy score
    pub accuracy_score: f64,
    /// False positive score (lower is better)
    pub false_positive_score: f64,
    /// Performance score
    pub performance_score: f64,
    /// Reliability score (consistency over time)
    pub reliability_score: f64,
    /// Total matches
    pub total_matches: u64,
    /// Confirmed true positives
    pub true_positives: u64,
    /// Confirmed false positives
    pub false_positives: u64,
    /// Pending verification
    pub pending_verification: u64,
    /// False positive rate (0.0 - 1.0)
    pub false_positive_rate: f64,
    /// True positive rate (0.0 - 1.0)
    pub true_positive_rate: f64,
    /// Average scan time in milliseconds
    pub avg_scan_time_ms: f64,
    /// Last match timestamp
    pub last_match_at: Option<DateTime<Utc>>,
    /// When score was last calculated
    pub calculated_at: DateTime<Utc>,
    /// Score trend (positive = improving, negative = degrading)
    pub trend: f64,
    /// Confidence level in the score (0.0 - 1.0)
    pub confidence: f64,
    /// Grade based on score (A-F)
    pub grade: EffectivenessGrade,
}

/// Effectiveness grade
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EffectivenessGrade {
    A,
    B,
    C,
    D,
    F,
}

impl EffectivenessGrade {
    pub fn from_score(score: f64) -> Self {
        if score >= 90.0 {
            Self::A
        } else if score >= 80.0 {
            Self::B
        } else if score >= 70.0 {
            Self::C
        } else if score >= 60.0 {
            Self::D
        } else {
            Self::F
        }
    }
}

impl std::fmt::Display for EffectivenessGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffectivenessGrade::A => write!(f, "A"),
            EffectivenessGrade::B => write!(f, "B"),
            EffectivenessGrade::C => write!(f, "C"),
            EffectivenessGrade::D => write!(f, "D"),
            EffectivenessGrade::F => write!(f, "F"),
        }
    }
}

/// A match event for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEvent {
    /// Unique match ID
    pub id: String,
    /// Rule ID that matched
    pub rule_id: String,
    /// File path that was matched
    pub file_path: String,
    /// File hash
    pub file_hash: Option<String>,
    /// Scan time in milliseconds
    pub scan_time_ms: u64,
    /// Match timestamp
    pub matched_at: DateTime<Utc>,
    /// Verification status
    pub verification_status: VerificationStatus,
    /// Verified by user ID
    pub verified_by: Option<String>,
    /// Verified at timestamp
    pub verified_at: Option<DateTime<Utc>>,
    /// Verification notes
    pub notes: Option<String>,
}

/// Verification status for a match
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Pending verification
    Pending,
    /// Confirmed true positive
    TruePositive,
    /// Confirmed false positive
    FalsePositive,
    /// Unable to determine
    Inconclusive,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationStatus::Pending => write!(f, "pending"),
            VerificationStatus::TruePositive => write!(f, "true_positive"),
            VerificationStatus::FalsePositive => write!(f, "false_positive"),
            VerificationStatus::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// Historical effectiveness data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessDataPoint {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Score at this time
    pub score: f64,
    /// Total matches at this time
    pub total_matches: u64,
    /// False positive rate at this time
    pub false_positive_rate: f64,
}

/// Configuration for effectiveness scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivenessConfig {
    /// Weight for accuracy component (0.0 - 1.0)
    pub accuracy_weight: f64,
    /// Weight for false positive component (0.0 - 1.0)
    pub false_positive_weight: f64,
    /// Weight for performance component (0.0 - 1.0)
    pub performance_weight: f64,
    /// Weight for reliability component (0.0 - 1.0)
    pub reliability_weight: f64,
    /// Minimum matches required for confident scoring
    pub min_matches_for_confidence: u64,
    /// Target scan time for 100% performance score (ms)
    pub target_scan_time_ms: f64,
    /// Maximum acceptable false positive rate
    pub max_acceptable_fp_rate: f64,
    /// Days of history to consider for trends
    pub trend_days: u32,
}

impl Default for EffectivenessConfig {
    fn default() -> Self {
        Self {
            accuracy_weight: 0.35,
            false_positive_weight: 0.35,
            performance_weight: 0.15,
            reliability_weight: 0.15,
            min_matches_for_confidence: 10,
            target_scan_time_ms: 50.0,
            max_acceptable_fp_rate: 0.10, // 10%
            trend_days: 30,
        }
    }
}

// ============================================================================
// Effectiveness Calculator
// ============================================================================

/// Calculates effectiveness scores for YARA rules
pub struct EffectivenessCalculator {
    config: EffectivenessConfig,
}

impl EffectivenessCalculator {
    /// Create a new calculator with default config
    pub fn new() -> Self {
        Self {
            config: EffectivenessConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: EffectivenessConfig) -> Self {
        Self { config }
    }

    /// Calculate effectiveness score for a rule based on its statistics
    pub fn calculate_score(
        &self,
        rule_id: &str,
        rule_name: &str,
        stats: &RuleMatchStats,
        historical: &[EffectivenessDataPoint],
    ) -> RuleEffectivenessScore {
        // Calculate accuracy score (based on true positive rate)
        let accuracy_score = self.calculate_accuracy_score(stats);

        // Calculate false positive score (inverse - lower FP rate = higher score)
        let false_positive_score = self.calculate_fp_score(stats);

        // Calculate performance score (based on scan time)
        let performance_score = self.calculate_performance_score(stats);

        // Calculate reliability score (based on consistency over time)
        let reliability_score = self.calculate_reliability_score(stats, historical);

        // Calculate weighted overall score
        let score = accuracy_score * self.config.accuracy_weight
            + false_positive_score * self.config.false_positive_weight
            + performance_score * self.config.performance_weight
            + reliability_score * self.config.reliability_weight;

        // Normalize to 0-100
        let score = score.min(100.0).max(0.0);

        // Calculate confidence based on sample size
        let confidence = self.calculate_confidence(stats);

        // Calculate trend
        let trend = self.calculate_trend(historical);

        RuleEffectivenessScore {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            score,
            accuracy_score,
            false_positive_score,
            performance_score,
            reliability_score,
            total_matches: stats.total_matches,
            true_positives: stats.true_positives,
            false_positives: stats.false_positives,
            pending_verification: stats.pending_verification,
            false_positive_rate: stats.false_positive_rate(),
            true_positive_rate: stats.true_positive_rate(),
            avg_scan_time_ms: stats.avg_scan_time_ms,
            last_match_at: stats.last_match_at,
            calculated_at: Utc::now(),
            trend,
            confidence,
            grade: EffectivenessGrade::from_score(score),
        }
    }

    /// Calculate accuracy score (0-100)
    fn calculate_accuracy_score(&self, stats: &RuleMatchStats) -> f64 {
        if stats.total_verified() == 0 {
            return 50.0; // Default score with no data
        }

        // True positive rate as percentage
        stats.true_positive_rate() * 100.0
    }

    /// Calculate false positive score (0-100, higher = fewer FPs)
    fn calculate_fp_score(&self, stats: &RuleMatchStats) -> f64 {
        if stats.total_verified() == 0 {
            return 50.0; // Default score with no data
        }

        let fp_rate = stats.false_positive_rate();

        // Score decreases as FP rate increases
        // At max_acceptable_fp_rate or higher, score is 0
        if fp_rate >= self.config.max_acceptable_fp_rate {
            return 0.0;
        }

        // Linear interpolation: 0% FP = 100, max_acceptable% = 0
        (1.0 - fp_rate / self.config.max_acceptable_fp_rate) * 100.0
    }

    /// Calculate performance score (0-100)
    fn calculate_performance_score(&self, stats: &RuleMatchStats) -> f64 {
        if stats.total_matches == 0 || stats.avg_scan_time_ms <= 0.0 {
            return 100.0; // Assume perfect performance with no data
        }

        // Score based on how close to target scan time
        if stats.avg_scan_time_ms <= self.config.target_scan_time_ms {
            return 100.0;
        }

        // Linear decrease: at 2x target = 50%, at 4x target = 0%
        let ratio = stats.avg_scan_time_ms / self.config.target_scan_time_ms;
        let score = 100.0 - (ratio - 1.0) * 33.33;

        score.max(0.0)
    }

    /// Calculate reliability score (0-100)
    fn calculate_reliability_score(&self, stats: &RuleMatchStats, historical: &[EffectivenessDataPoint]) -> f64 {
        if historical.len() < 2 {
            return 50.0; // Default with insufficient data
        }

        // Calculate variance in scores over time
        let scores: Vec<f64> = historical.iter().map(|h| h.score).collect();
        let mean = scores.iter().sum::<f64>() / scores.len() as f64;
        let variance = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / scores.len() as f64;
        let std_dev = variance.sqrt();

        // Lower variance = higher reliability
        // Score 100 if std_dev < 5, decreasing as variance increases
        if std_dev < 5.0 {
            return 100.0;
        }

        let score = 100.0 - (std_dev - 5.0) * 5.0;
        score.max(0.0)
    }

    /// Calculate confidence level (0-1)
    fn calculate_confidence(&self, stats: &RuleMatchStats) -> f64 {
        if stats.total_matches == 0 {
            return 0.0;
        }

        // Confidence grows with sample size
        let verified_count = stats.total_verified();
        let confidence = (verified_count as f64 / self.config.min_matches_for_confidence as f64).min(1.0);

        // Weight verified matches higher
        let verification_bonus = if verified_count > 0 {
            (verified_count as f64 / stats.total_matches as f64) * 0.2
        } else {
            0.0
        };

        (confidence + verification_bonus).min(1.0)
    }

    /// Calculate trend from historical data
    fn calculate_trend(&self, historical: &[EffectivenessDataPoint]) -> f64 {
        if historical.len() < 2 {
            return 0.0;
        }

        // Simple linear trend calculation
        let n = historical.len() as f64;
        let sum_x: f64 = (0..historical.len()).map(|i| i as f64).sum();
        let sum_y: f64 = historical.iter().map(|h| h.score).sum();
        let sum_xy: f64 = historical.iter().enumerate().map(|(i, h)| i as f64 * h.score).sum();
        let sum_xx: f64 = (0..historical.len()).map(|i| (i as f64).powi(2)).sum();

        // Slope of linear regression
        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_xx - sum_x.powi(2));

        // Normalize to -10 to +10 range
        slope.max(-10.0).min(10.0)
    }
}

impl Default for EffectivenessCalculator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Rule Match Statistics
// ============================================================================

/// Accumulated match statistics for a rule
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMatchStats {
    /// Total matches
    pub total_matches: u64,
    /// Confirmed true positives
    pub true_positives: u64,
    /// Confirmed false positives
    pub false_positives: u64,
    /// Pending verification
    pub pending_verification: u64,
    /// Inconclusive matches
    pub inconclusive: u64,
    /// Average scan time in ms
    pub avg_scan_time_ms: f64,
    /// Maximum scan time in ms
    pub max_scan_time_ms: f64,
    /// Minimum scan time in ms
    pub min_scan_time_ms: f64,
    /// Total scan time for averaging
    pub total_scan_time_ms: f64,
    /// Unique files matched
    pub unique_files: u64,
    /// Last match timestamp
    pub last_match_at: Option<DateTime<Utc>>,
}

impl RuleMatchStats {
    /// Add a match event to statistics
    pub fn add_match(&mut self, event: &MatchEvent) {
        self.total_matches += 1;

        // Update verification counts
        match event.verification_status {
            VerificationStatus::TruePositive => self.true_positives += 1,
            VerificationStatus::FalsePositive => self.false_positives += 1,
            VerificationStatus::Pending => self.pending_verification += 1,
            VerificationStatus::Inconclusive => self.inconclusive += 1,
        }

        // Update scan time stats
        let scan_time = event.scan_time_ms as f64;
        self.total_scan_time_ms += scan_time;
        self.avg_scan_time_ms = self.total_scan_time_ms / self.total_matches as f64;

        if self.max_scan_time_ms == 0.0 || scan_time > self.max_scan_time_ms {
            self.max_scan_time_ms = scan_time;
        }
        if self.min_scan_time_ms == 0.0 || scan_time < self.min_scan_time_ms {
            self.min_scan_time_ms = scan_time;
        }

        self.last_match_at = Some(event.matched_at);
    }

    /// Update verification status for a match
    pub fn update_verification(&mut self, old_status: VerificationStatus, new_status: VerificationStatus) {
        // Decrement old status
        match old_status {
            VerificationStatus::TruePositive => self.true_positives = self.true_positives.saturating_sub(1),
            VerificationStatus::FalsePositive => self.false_positives = self.false_positives.saturating_sub(1),
            VerificationStatus::Pending => self.pending_verification = self.pending_verification.saturating_sub(1),
            VerificationStatus::Inconclusive => self.inconclusive = self.inconclusive.saturating_sub(1),
        }

        // Increment new status
        match new_status {
            VerificationStatus::TruePositive => self.true_positives += 1,
            VerificationStatus::FalsePositive => self.false_positives += 1,
            VerificationStatus::Pending => self.pending_verification += 1,
            VerificationStatus::Inconclusive => self.inconclusive += 1,
        }
    }

    /// Total verified matches (true + false positives)
    pub fn total_verified(&self) -> u64 {
        self.true_positives + self.false_positives
    }

    /// False positive rate (0-1)
    pub fn false_positive_rate(&self) -> f64 {
        let total = self.total_verified();
        if total == 0 {
            return 0.0;
        }
        self.false_positives as f64 / total as f64
    }

    /// True positive rate (0-1)
    pub fn true_positive_rate(&self) -> f64 {
        let total = self.total_verified();
        if total == 0 {
            return 0.0;
        }
        self.true_positives as f64 / total as f64
    }

    /// Precision (true positives / (true positives + false positives))
    pub fn precision(&self) -> f64 {
        self.true_positive_rate()
    }
}

// ============================================================================
// Effectiveness Tracker
// ============================================================================

/// Tracks and manages effectiveness data for multiple rules
pub struct EffectivenessTracker {
    /// Statistics per rule
    stats: HashMap<String, RuleMatchStats>,
    /// Historical data per rule
    history: HashMap<String, Vec<EffectivenessDataPoint>>,
    /// Calculator
    calculator: EffectivenessCalculator,
    /// Rule name mapping
    rule_names: HashMap<String, String>,
}

impl EffectivenessTracker {
    /// Create a new tracker
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
            history: HashMap::new(),
            calculator: EffectivenessCalculator::new(),
            rule_names: HashMap::new(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: EffectivenessConfig) -> Self {
        Self {
            stats: HashMap::new(),
            history: HashMap::new(),
            calculator: EffectivenessCalculator::with_config(config),
            rule_names: HashMap::new(),
        }
    }

    /// Register a rule for tracking
    pub fn register_rule(&mut self, rule_id: &str, rule_name: &str) {
        self.rule_names.insert(rule_id.to_string(), rule_name.to_string());
        if !self.stats.contains_key(rule_id) {
            self.stats.insert(rule_id.to_string(), RuleMatchStats::default());
        }
        if !self.history.contains_key(rule_id) {
            self.history.insert(rule_id.to_string(), Vec::new());
        }
    }

    /// Record a match event
    pub fn record_match(&mut self, event: &MatchEvent) {
        let stats = self.stats.entry(event.rule_id.clone()).or_insert_with(RuleMatchStats::default);
        stats.add_match(event);
    }

    /// Update verification status for a match
    pub fn update_verification(&mut self, rule_id: &str, old_status: VerificationStatus, new_status: VerificationStatus) {
        if let Some(stats) = self.stats.get_mut(rule_id) {
            stats.update_verification(old_status, new_status);
        }
    }

    /// Get current effectiveness score for a rule
    pub fn get_score(&self, rule_id: &str) -> Option<RuleEffectivenessScore> {
        let stats = self.stats.get(rule_id)?;
        let history = self.history.get(rule_id).map(|h| h.as_slice()).unwrap_or(&[]);
        let rule_name = self.rule_names.get(rule_id).cloned().unwrap_or_else(|| rule_id.to_string());

        Some(self.calculator.calculate_score(rule_id, &rule_name, stats, history))
    }

    /// Get scores for all rules
    pub fn get_all_scores(&self) -> Vec<RuleEffectivenessScore> {
        self.stats
            .keys()
            .filter_map(|id| self.get_score(id))
            .collect()
    }

    /// Get statistics for a rule
    pub fn get_stats(&self, rule_id: &str) -> Option<&RuleMatchStats> {
        self.stats.get(rule_id)
    }

    /// Record a historical data point
    pub fn record_history(&mut self, rule_id: &str, data_point: EffectivenessDataPoint) {
        let history = self.history.entry(rule_id.to_string()).or_insert_with(Vec::new);
        history.push(data_point);

        // Keep only last 90 days of history
        let cutoff = Utc::now() - Duration::days(90);
        history.retain(|h| h.timestamp > cutoff);
    }

    /// Get historical data for a rule
    pub fn get_history(&self, rule_id: &str) -> Option<&Vec<EffectivenessDataPoint>> {
        self.history.get(rule_id)
    }

    /// Get rules that need review (low scores or high FP rate)
    pub fn get_rules_needing_review(&self, min_score: f64, max_fp_rate: f64) -> Vec<RuleEffectivenessScore> {
        self.get_all_scores()
            .into_iter()
            .filter(|s| s.score < min_score || s.false_positive_rate > max_fp_rate)
            .collect()
    }

    /// Get top performing rules
    pub fn get_top_performers(&self, limit: usize) -> Vec<RuleEffectivenessScore> {
        let mut scores = self.get_all_scores();
        scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(limit);
        scores
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> EffectivenessSummary {
        let scores = self.get_all_scores();

        if scores.is_empty() {
            return EffectivenessSummary::default();
        }

        let total_rules = scores.len();
        let avg_score = scores.iter().map(|s| s.score).sum::<f64>() / total_rules as f64;
        let total_matches: u64 = scores.iter().map(|s| s.total_matches).sum();
        let total_fp: u64 = scores.iter().map(|s| s.false_positives).sum();
        let total_tp: u64 = scores.iter().map(|s| s.true_positives).sum();

        let by_grade = |grade: EffectivenessGrade| scores.iter().filter(|s| s.grade == grade).count();

        EffectivenessSummary {
            total_rules,
            avg_score,
            total_matches,
            total_false_positives: total_fp,
            total_true_positives: total_tp,
            overall_fp_rate: if total_tp + total_fp > 0 {
                total_fp as f64 / (total_tp + total_fp) as f64
            } else {
                0.0
            },
            grade_a_count: by_grade(EffectivenessGrade::A),
            grade_b_count: by_grade(EffectivenessGrade::B),
            grade_c_count: by_grade(EffectivenessGrade::C),
            grade_d_count: by_grade(EffectivenessGrade::D),
            grade_f_count: by_grade(EffectivenessGrade::F),
        }
    }
}

impl Default for EffectivenessTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics for all rules
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EffectivenessSummary {
    /// Total tracked rules
    pub total_rules: usize,
    /// Average effectiveness score
    pub avg_score: f64,
    /// Total matches across all rules
    pub total_matches: u64,
    /// Total false positives
    pub total_false_positives: u64,
    /// Total true positives
    pub total_true_positives: u64,
    /// Overall false positive rate
    pub overall_fp_rate: f64,
    /// Rules with grade A
    pub grade_a_count: usize,
    /// Rules with grade B
    pub grade_b_count: usize,
    /// Rules with grade C
    pub grade_c_count: usize,
    /// Rules with grade D
    pub grade_d_count: usize,
    /// Rules with grade F
    pub grade_f_count: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effectiveness_grade() {
        assert_eq!(EffectivenessGrade::from_score(95.0), EffectivenessGrade::A);
        assert_eq!(EffectivenessGrade::from_score(85.0), EffectivenessGrade::B);
        assert_eq!(EffectivenessGrade::from_score(75.0), EffectivenessGrade::C);
        assert_eq!(EffectivenessGrade::from_score(65.0), EffectivenessGrade::D);
        assert_eq!(EffectivenessGrade::from_score(50.0), EffectivenessGrade::F);
    }

    #[test]
    fn test_rule_match_stats() {
        let mut stats = RuleMatchStats::default();

        let event = MatchEvent {
            id: "1".to_string(),
            rule_id: "rule1".to_string(),
            file_path: "/test/file".to_string(),
            file_hash: None,
            scan_time_ms: 100,
            matched_at: Utc::now(),
            verification_status: VerificationStatus::TruePositive,
            verified_by: None,
            verified_at: None,
            notes: None,
        };

        stats.add_match(&event);
        assert_eq!(stats.total_matches, 1);
        assert_eq!(stats.true_positives, 1);
        assert_eq!(stats.avg_scan_time_ms, 100.0);
    }

    #[test]
    fn test_effectiveness_calculator() {
        let calculator = EffectivenessCalculator::new();

        let stats = RuleMatchStats {
            total_matches: 100,
            true_positives: 95,
            false_positives: 5,
            pending_verification: 0,
            inconclusive: 0,
            avg_scan_time_ms: 25.0,
            max_scan_time_ms: 50.0,
            min_scan_time_ms: 10.0,
            total_scan_time_ms: 2500.0,
            unique_files: 95,
            last_match_at: Some(Utc::now()),
        };

        let score = calculator.calculate_score("rule1", "Test Rule", &stats, &[]);

        assert!(score.score > 70.0, "Expected score > 70.0, got {}", score.score);
        assert_eq!(score.true_positives, 95);
        assert_eq!(score.false_positives, 5);
        assert!(score.false_positive_rate - 0.05 < 0.001);
    }

    #[test]
    fn test_effectiveness_tracker() {
        let mut tracker = EffectivenessTracker::new();

        tracker.register_rule("rule1", "Test Rule 1");
        tracker.register_rule("rule2", "Test Rule 2");

        let event1 = MatchEvent {
            id: "1".to_string(),
            rule_id: "rule1".to_string(),
            file_path: "/test/file1".to_string(),
            file_hash: None,
            scan_time_ms: 50,
            matched_at: Utc::now(),
            verification_status: VerificationStatus::TruePositive,
            verified_by: None,
            verified_at: None,
            notes: None,
        };

        tracker.record_match(&event1);

        let stats = tracker.get_stats("rule1").unwrap();
        assert_eq!(stats.total_matches, 1);

        let score = tracker.get_score("rule1").unwrap();
        assert!(score.score > 0.0);
    }
}
