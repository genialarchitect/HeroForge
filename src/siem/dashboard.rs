//! SIEM Dashboard Module for HeroForge
//!
//! This module provides dashboard functionality including:
//! - Saved searches with scheduling
//! - Dashboard widgets (alert counts, top sources, trends)
//! - Quick filters and time range selection
//! - Alert deduplication and management
//!
//! # Features
//!
//! - **Saved Searches**: Store and schedule recurring searches
//! - **Dashboard Widgets**: Configurable widgets for security metrics
//! - **Alert Deduplication**: Group similar alerts to reduce noise
//! - **Time Range Selection**: Quick filters for common time ranges
//! - **Alert Workflow**: Status management (new -> acknowledged -> investigating -> resolved)

#![allow(dead_code)]

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::types::{AlertStatus, LogQuery, SiemAlert, SiemSeverity};

// ============================================================================
// Saved Searches
// ============================================================================

/// A saved search configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSearch {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// The search query (SPL-like syntax or JSON)
    pub query: String,
    /// Parsed query parameters
    pub query_params: LogQuery,
    /// Cron schedule for automatic execution (optional)
    pub schedule_cron: Option<String>,
    /// Whether scheduled execution is enabled
    pub schedule_enabled: bool,
    /// Alert threshold (generate alert if results exceed)
    pub alert_threshold: Option<i64>,
    /// Severity for generated alerts
    pub alert_severity: Option<SiemSeverity>,
    /// Email recipients for scheduled results
    pub email_recipients: Vec<String>,
    /// Last execution time
    pub last_run: Option<DateTime<Utc>>,
    /// Last execution result count
    pub last_result_count: Option<i64>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// User who created the search
    pub user_id: String,
    /// Organization ID (for multi-tenancy)
    pub organization_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SavedSearch {
    pub fn new(name: String, query: String, user_id: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description: None,
            query,
            query_params: LogQuery::new(),
            schedule_cron: None,
            schedule_enabled: false,
            alert_threshold: None,
            alert_severity: None,
            email_recipients: Vec::new(),
            last_run: None,
            last_result_count: None,
            tags: Vec::new(),
            user_id,
            organization_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Result of executing a saved search
#[derive(Debug, Clone, Serialize)]
pub struct SavedSearchResult {
    pub search_id: String,
    pub search_name: String,
    pub executed_at: DateTime<Utc>,
    pub execution_time_ms: u64,
    pub result_count: i64,
    pub threshold_exceeded: bool,
    pub generated_alert_id: Option<String>,
}

// ============================================================================
// Dashboard Widgets
// ============================================================================

/// Type of dashboard widget
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidgetType {
    /// Simple number counter
    Counter,
    /// Time series chart
    TimeSeries,
    /// Pie/donut chart
    PieChart,
    /// Bar chart
    BarChart,
    /// Data table
    Table,
    /// Top N list
    TopList,
    /// Geographic map
    GeoMap,
    /// Alert summary
    AlertSummary,
    /// Single value with trend
    SingleValue,
    /// Status indicator
    StatusIndicator,
}

impl WidgetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::TimeSeries => "time_series",
            Self::PieChart => "pie_chart",
            Self::BarChart => "bar_chart",
            Self::Table => "table",
            Self::TopList => "top_list",
            Self::GeoMap => "geo_map",
            Self::AlertSummary => "alert_summary",
            Self::SingleValue => "single_value",
            Self::StatusIndicator => "status_indicator",
        }
    }
}

/// Widget position on dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetPosition {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl Default for WidgetPosition {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            width: 4,
            height: 3,
        }
    }
}

/// Configuration for a dashboard widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfig {
    /// Widget title
    pub title: String,
    /// Data source query
    pub query: Option<String>,
    /// Saved search ID to use as data source
    pub saved_search_id: Option<String>,
    /// Time range override (e.g., "1h", "24h", "7d")
    pub time_range: Option<String>,
    /// Refresh interval in seconds
    pub refresh_interval: Option<i32>,
    /// Chart-specific options
    pub chart_options: HashMap<String, serde_json::Value>,
    /// Drilldown query/URL
    pub drilldown: Option<String>,
    /// Threshold values for coloring
    pub thresholds: Option<Vec<ThresholdConfig>>,
}

impl Default for WidgetConfig {
    fn default() -> Self {
        Self {
            title: "Untitled Widget".to_string(),
            query: None,
            saved_search_id: None,
            time_range: None,
            refresh_interval: Some(60),
            chart_options: HashMap::new(),
            drilldown: None,
            thresholds: None,
        }
    }
}

/// Threshold configuration for widgets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub value: f64,
    pub color: String,
    pub label: Option<String>,
}

/// A dashboard widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardWidget {
    pub id: String,
    pub dashboard_id: String,
    pub widget_type: WidgetType,
    pub position: WidgetPosition,
    pub config: WidgetConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DashboardWidget {
    pub fn new(dashboard_id: String, widget_type: WidgetType, title: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id,
            widget_type,
            position: WidgetPosition::default(),
            config: WidgetConfig {
                title,
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        }
    }
}

/// A SIEM dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemDashboard {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Default time range for all widgets
    pub default_time_range: String,
    /// Auto-refresh interval in seconds (0 = disabled)
    pub auto_refresh: i32,
    /// Dashboard widgets
    pub widgets: Vec<DashboardWidget>,
    /// Shared with all users
    pub is_public: bool,
    /// Owner user ID
    pub user_id: String,
    /// Organization ID
    pub organization_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SiemDashboard {
    pub fn new(name: String, user_id: String) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description: None,
            default_time_range: "24h".to_string(),
            auto_refresh: 60,
            widgets: Vec::new(),
            is_public: false,
            user_id,
            organization_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

// ============================================================================
// Dashboard Data Types
// ============================================================================

/// Time range selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeRange {
    Last15Minutes,
    Last1Hour,
    Last4Hours,
    Last24Hours,
    Last7Days,
    Last30Days,
    Last90Days,
    Custom,
}

impl TimeRange {
    pub fn to_duration(&self) -> Option<Duration> {
        match self {
            Self::Last15Minutes => Some(Duration::minutes(15)),
            Self::Last1Hour => Some(Duration::hours(1)),
            Self::Last4Hours => Some(Duration::hours(4)),
            Self::Last24Hours => Some(Duration::hours(24)),
            Self::Last7Days => Some(Duration::days(7)),
            Self::Last30Days => Some(Duration::days(30)),
            Self::Last90Days => Some(Duration::days(90)),
            Self::Custom => None,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "15m" | "15min" => Self::Last15Minutes,
            "1h" | "hour" => Self::Last1Hour,
            "4h" => Self::Last4Hours,
            "24h" | "1d" | "day" => Self::Last24Hours,
            "7d" | "week" => Self::Last7Days,
            "30d" | "month" => Self::Last30Days,
            "90d" | "quarter" => Self::Last90Days,
            _ => Self::Last24Hours,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Last15Minutes => "15m",
            Self::Last1Hour => "1h",
            Self::Last4Hours => "4h",
            Self::Last24Hours => "24h",
            Self::Last7Days => "7d",
            Self::Last30Days => "30d",
            Self::Last90Days => "90d",
            Self::Custom => "custom",
        }
    }
}

/// Dashboard overview data
#[derive(Debug, Clone, Serialize)]
pub struct DashboardOverview {
    /// Total alerts count
    pub total_alerts: i64,
    /// Open (unresolved) alerts
    pub open_alerts: i64,
    /// Critical severity alerts
    pub critical_alerts: i64,
    /// High severity alerts
    pub high_alerts: i64,
    /// Medium severity alerts
    pub medium_alerts: i64,
    /// Low severity alerts
    pub low_alerts: i64,
    /// Alerts by status
    pub alerts_by_status: HashMap<String, i64>,
    /// Top alerting rules
    pub top_rules: Vec<RuleAlertCount>,
    /// Top sources by log count
    pub top_sources: Vec<SourceLogCount>,
    /// Alert trend (hourly counts for last 24h)
    pub alert_trend: Vec<TrendDataPoint>,
    /// Log ingestion rate (logs per second)
    pub ingestion_rate: f64,
    /// Total logs today
    pub logs_today: i64,
    /// Active correlation rules
    pub active_correlation_rules: i64,
    /// Active Sigma rules
    pub active_sigma_rules: i64,
}

/// Rule alert count for top rules
#[derive(Debug, Clone, Serialize)]
pub struct RuleAlertCount {
    pub rule_id: String,
    pub rule_name: String,
    pub alert_count: i64,
}

/// Source log count for top sources
#[derive(Debug, Clone, Serialize)]
pub struct SourceLogCount {
    pub source_id: String,
    pub source_name: String,
    pub log_count: i64,
    pub logs_per_hour: f64,
}

/// Trend data point
#[derive(Debug, Clone, Serialize)]
pub struct TrendDataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
    pub label: Option<String>,
}

// ============================================================================
// Alert Deduplication
// ============================================================================

/// Configuration for alert deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    /// Time window for grouping alerts (seconds)
    pub time_window_secs: i64,
    /// Fields to use for grouping
    pub group_by_fields: Vec<String>,
    /// Maximum alerts to group
    pub max_group_size: i32,
    /// Whether to auto-suppress duplicates
    pub auto_suppress: bool,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            time_window_secs: 300, // 5 minutes
            group_by_fields: vec!["rule_id".to_string(), "severity".to_string()],
            max_group_size: 100,
            auto_suppress: false,
        }
    }
}

/// A deduplicated alert group
#[derive(Debug, Clone, Serialize)]
pub struct AlertGroup {
    pub group_id: String,
    /// First alert in the group
    pub primary_alert: SiemAlert,
    /// Count of alerts in this group
    pub alert_count: i64,
    /// IDs of all alerts in the group
    pub alert_ids: Vec<String>,
    /// First occurrence time
    pub first_seen: DateTime<Utc>,
    /// Last occurrence time
    pub last_seen: DateTime<Utc>,
    /// Common fields in this group
    pub common_fields: HashMap<String, String>,
    /// Suppressed (hidden in UI)
    pub suppressed: bool,
}

/// Alert deduplication service
pub struct AlertDeduplicator {
    config: DeduplicationConfig,
    /// Active groups (group_key -> AlertGroup)
    groups: HashMap<String, AlertGroup>,
}

impl AlertDeduplicator {
    pub fn new(config: DeduplicationConfig) -> Self {
        Self {
            config,
            groups: HashMap::new(),
        }
    }

    /// Add an alert and return its group
    pub fn add_alert(&mut self, alert: SiemAlert) -> &AlertGroup {
        let group_key = self.compute_group_key(&alert);
        let now = Utc::now();
        let window = Duration::seconds(self.config.time_window_secs);
        let auto_suppress = self.config.auto_suppress;
        let max_group_size = self.config.max_group_size;

        // Check if group exists and get its last_seen time
        let needs_new_group = if let Some(existing) = self.groups.get(&group_key) {
            now - existing.last_seen > window
        } else {
            true
        };

        if needs_new_group {
            // Compute common fields before inserting
            let common_fields = self.extract_common_fields(&alert);
            self.groups.insert(group_key.clone(), AlertGroup {
                group_id: uuid::Uuid::new_v4().to_string(),
                primary_alert: alert.clone(),
                alert_count: 1,
                alert_ids: vec![alert.id.clone()],
                first_seen: alert.created_at,
                last_seen: alert.created_at,
                common_fields,
                suppressed: false,
            });
        } else {
            // Add to existing group
            let group = self.groups.get_mut(&group_key).unwrap();
            group.alert_count += 1;
            group.last_seen = alert.created_at;
            if group.alert_ids.len() < max_group_size as usize {
                group.alert_ids.push(alert.id.clone());
            }

            // Auto-suppress if enabled and exceeds threshold
            if auto_suppress && group.alert_count > 10 {
                group.suppressed = true;
            }
        }

        &self.groups[&group_key]
    }

    /// Get deduplicated alert groups
    pub fn get_groups(&self) -> Vec<&AlertGroup> {
        self.groups.values().collect()
    }

    /// Get non-suppressed groups
    pub fn get_active_groups(&self) -> Vec<&AlertGroup> {
        self.groups.values()
            .filter(|g| !g.suppressed)
            .collect()
    }

    /// Clean up old groups
    pub fn cleanup_expired(&mut self, max_age: Duration) {
        let now = Utc::now();
        self.groups.retain(|_, group| {
            now - group.last_seen < max_age
        });
    }

    fn compute_group_key(&self, alert: &SiemAlert) -> String {
        let mut key_parts = Vec::new();

        for field in &self.config.group_by_fields {
            let value = match field.as_str() {
                "rule_id" => alert.rule_id.clone(),
                "severity" => alert.severity.as_str().to_string(),
                "source_ip" => alert.source_ips.first().cloned().unwrap_or_default(),
                "destination_ip" => alert.destination_ips.first().cloned().unwrap_or_default(),
                "user" => alert.users.first().cloned().unwrap_or_default(),
                "host" => alert.hosts.first().cloned().unwrap_or_default(),
                _ => String::new(),
            };
            key_parts.push(value);
        }

        key_parts.join("|")
    }

    fn extract_common_fields(&self, alert: &SiemAlert) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        fields.insert("rule_id".to_string(), alert.rule_id.clone());
        fields.insert("rule_name".to_string(), alert.rule_name.clone());
        fields.insert("severity".to_string(), alert.severity.as_str().to_string());
        if let Some(ip) = alert.source_ips.first() {
            fields.insert("source_ip".to_string(), ip.clone());
        }
        if let Some(host) = alert.hosts.first() {
            fields.insert("host".to_string(), host.clone());
        }
        fields
    }
}

// ============================================================================
// Alert Severity Scoring
// ============================================================================

/// Factors that influence alert severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityFactors {
    /// Base severity from rule
    pub base_severity: SiemSeverity,
    /// Asset criticality (1-10)
    pub asset_criticality: Option<i32>,
    /// Number of affected assets
    pub affected_assets: i32,
    /// Matches known threat intelligence
    pub threat_intel_match: bool,
    /// Attack chain progression (0.0 - 1.0)
    pub attack_chain_progress: f32,
    /// False positive history for this rule (0.0 - 1.0)
    pub false_positive_rate: f32,
    /// Time since last similar alert
    pub recency_factor: f32,
}

/// Alert severity scoring engine
pub struct SeverityScorer;

impl SeverityScorer {
    /// Calculate overall severity score (0-100)
    pub fn calculate_score(factors: &SeverityFactors) -> i32 {
        let mut score: f32 = match factors.base_severity {
            SiemSeverity::Debug => 10.0,
            SiemSeverity::Info => 20.0,
            SiemSeverity::Notice => 30.0,
            SiemSeverity::Warning => 50.0,
            SiemSeverity::Error => 70.0,
            SiemSeverity::Critical => 85.0,
            SiemSeverity::Alert => 90.0,
            SiemSeverity::Emergency => 100.0,
        };

        // Asset criticality boost (up to +15)
        if let Some(criticality) = factors.asset_criticality {
            score += (criticality as f32 / 10.0) * 15.0;
        }

        // Affected assets boost (up to +10)
        score += (factors.affected_assets.min(10) as f32) * 1.0;

        // Threat intel match boost (+20)
        if factors.threat_intel_match {
            score += 20.0;
        }

        // Attack chain progression boost (up to +15)
        score += factors.attack_chain_progress * 15.0;

        // False positive reduction (up to -30)
        score -= factors.false_positive_rate * 30.0;

        // Recency boost/penalty (up to +/- 10)
        score += (0.5 - factors.recency_factor) * 20.0;

        score.round().max(0.0).min(100.0) as i32
    }

    /// Determine effective severity from score
    pub fn score_to_severity(score: i32) -> SiemSeverity {
        match score {
            0..=20 => SiemSeverity::Info,
            21..=40 => SiemSeverity::Notice,
            41..=55 => SiemSeverity::Warning,
            56..=70 => SiemSeverity::Error,
            71..=85 => SiemSeverity::Critical,
            86..=95 => SiemSeverity::Alert,
            _ => SiemSeverity::Emergency,
        }
    }
}

// ============================================================================
// Alert Status Workflow
// ============================================================================

/// Alert status transition rules
pub struct AlertWorkflow;

impl AlertWorkflow {
    /// Get valid next statuses for current status
    pub fn get_valid_transitions(current: AlertStatus) -> Vec<AlertStatus> {
        match current {
            AlertStatus::New => vec![
                AlertStatus::InProgress,
                AlertStatus::Escalated,
                AlertStatus::Ignored,
                AlertStatus::FalsePositive,
            ],
            AlertStatus::InProgress => vec![
                AlertStatus::Resolved,
                AlertStatus::Escalated,
                AlertStatus::FalsePositive,
            ],
            AlertStatus::Escalated => vec![
                AlertStatus::InProgress,
                AlertStatus::Resolved,
            ],
            AlertStatus::Resolved => vec![
                AlertStatus::New, // Reopen
            ],
            AlertStatus::FalsePositive => vec![
                AlertStatus::New, // Reopen if incorrectly marked
            ],
            AlertStatus::Ignored => vec![
                AlertStatus::New, // Reopen
            ],
        }
    }

    /// Check if transition is valid
    pub fn is_valid_transition(from: AlertStatus, to: AlertStatus) -> bool {
        Self::get_valid_transitions(from).contains(&to)
    }

    /// Get human-readable status name
    pub fn status_display_name(status: AlertStatus) -> &'static str {
        match status {
            AlertStatus::New => "New",
            AlertStatus::InProgress => "Investigating",
            AlertStatus::Escalated => "Escalated",
            AlertStatus::Resolved => "Resolved",
            AlertStatus::FalsePositive => "False Positive",
            AlertStatus::Ignored => "Ignored",
        }
    }

    /// Get status color for UI
    pub fn status_color(status: AlertStatus) -> &'static str {
        match status {
            AlertStatus::New => "#dc3545",        // Red
            AlertStatus::InProgress => "#fd7e14", // Orange
            AlertStatus::Escalated => "#6f42c1",  // Purple
            AlertStatus::Resolved => "#28a745",   // Green
            AlertStatus::FalsePositive => "#6c757d", // Gray
            AlertStatus::Ignored => "#6c757d",    // Gray
        }
    }
}

// ============================================================================
// Built-in Dashboard Templates
// ============================================================================

/// Get default SIEM dashboard
pub fn get_default_dashboard(user_id: String) -> SiemDashboard {
    let now = Utc::now();
    let dashboard_id = uuid::Uuid::new_v4().to_string();

    let widgets = vec![
        // Alert count by severity
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::PieChart,
            position: WidgetPosition { x: 0, y: 0, width: 4, height: 3 },
            config: WidgetConfig {
                title: "Alerts by Severity".to_string(),
                query: Some("SELECT severity, COUNT(*) FROM siem_alerts GROUP BY severity".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Open alerts counter
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::Counter,
            position: WidgetPosition { x: 4, y: 0, width: 2, height: 2 },
            config: WidgetConfig {
                title: "Open Alerts".to_string(),
                query: Some("SELECT COUNT(*) FROM siem_alerts WHERE status IN ('new', 'in_progress')".to_string()),
                thresholds: Some(vec![
                    ThresholdConfig { value: 10.0, color: "#28a745".to_string(), label: Some("Normal".to_string()) },
                    ThresholdConfig { value: 50.0, color: "#fd7e14".to_string(), label: Some("Warning".to_string()) },
                    ThresholdConfig { value: 100.0, color: "#dc3545".to_string(), label: Some("Critical".to_string()) },
                ]),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Critical alerts counter
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::Counter,
            position: WidgetPosition { x: 6, y: 0, width: 2, height: 2 },
            config: WidgetConfig {
                title: "Critical Alerts".to_string(),
                query: Some("SELECT COUNT(*) FROM siem_alerts WHERE severity = 'critical' AND status NOT IN ('resolved', 'false_positive')".to_string()),
                thresholds: Some(vec![
                    ThresholdConfig { value: 0.0, color: "#28a745".to_string(), label: None },
                    ThresholdConfig { value: 1.0, color: "#dc3545".to_string(), label: None },
                ]),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Alert trend
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::TimeSeries,
            position: WidgetPosition { x: 8, y: 0, width: 4, height: 3 },
            config: WidgetConfig {
                title: "Alert Trend (24h)".to_string(),
                query: Some("SELECT strftime('%H', created_at) as hour, COUNT(*) FROM siem_alerts WHERE created_at > datetime('now', '-1 day') GROUP BY hour".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Top alerting rules
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::TopList,
            position: WidgetPosition { x: 0, y: 3, width: 6, height: 4 },
            config: WidgetConfig {
                title: "Top Alerting Rules".to_string(),
                query: Some("SELECT rule_name, COUNT(*) as count FROM siem_alerts GROUP BY rule_id ORDER BY count DESC LIMIT 10".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Top log sources
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::BarChart,
            position: WidgetPosition { x: 6, y: 3, width: 6, height: 4 },
            config: WidgetConfig {
                title: "Top Log Sources".to_string(),
                query: Some("SELECT name, log_count FROM siem_log_sources ORDER BY log_count DESC LIMIT 10".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
        // Recent alerts table
        DashboardWidget {
            id: uuid::Uuid::new_v4().to_string(),
            dashboard_id: dashboard_id.clone(),
            widget_type: WidgetType::Table,
            position: WidgetPosition { x: 0, y: 7, width: 12, height: 5 },
            config: WidgetConfig {
                title: "Recent Alerts".to_string(),
                query: Some("SELECT created_at, severity, rule_name, title, status FROM siem_alerts ORDER BY created_at DESC LIMIT 20".to_string()),
                ..Default::default()
            },
            created_at: now,
            updated_at: now,
        },
    ];

    SiemDashboard {
        id: dashboard_id,
        name: "SIEM Overview".to_string(),
        description: Some("Default SIEM dashboard with key security metrics".to_string()),
        default_time_range: "24h".to_string(),
        auto_refresh: 60,
        widgets,
        is_public: true,
        user_id,
        organization_id: None,
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_range_parsing() {
        assert_eq!(TimeRange::from_str("1h").as_str(), "1h");
        assert_eq!(TimeRange::from_str("24h").as_str(), "24h");
        assert_eq!(TimeRange::from_str("7d").as_str(), "7d");
    }

    #[test]
    fn test_severity_scoring() {
        let factors = SeverityFactors {
            base_severity: SiemSeverity::Warning,
            asset_criticality: Some(8),
            affected_assets: 5,
            threat_intel_match: true,
            attack_chain_progress: 0.5,
            false_positive_rate: 0.1,
            recency_factor: 0.3,
        };

        let score = SeverityScorer::calculate_score(&factors);
        assert!(score > 50, "Score should be elevated: {}", score);
        assert!(score < 100, "Score should not exceed 100: {}", score);
    }

    #[test]
    fn test_alert_workflow() {
        assert!(AlertWorkflow::is_valid_transition(AlertStatus::New, AlertStatus::InProgress));
        assert!(!AlertWorkflow::is_valid_transition(AlertStatus::Resolved, AlertStatus::InProgress));
        assert!(AlertWorkflow::is_valid_transition(AlertStatus::Resolved, AlertStatus::New));
    }

    #[test]
    fn test_default_dashboard() {
        let dashboard = get_default_dashboard("test-user".to_string());
        assert!(!dashboard.widgets.is_empty());
        assert!(dashboard.widgets.len() >= 5);
    }
}
