use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::models::*;

// ============================================================================
// Dashboard Configuration Models
// ============================================================================

/// User dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserDashboardConfig {
    pub user_id: String,
    pub widgets: String, // JSON array of widget configurations
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfig {
    pub id: String,
    pub widget_type: String, // e.g., "recent_scans", "vulnerability_summary", etc.
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub config: Option<serde_json::Value>, // Widget-specific configuration
}

/// Request to update dashboard configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateDashboardConfigRequest {
    pub widgets: Vec<WidgetConfig>,
}

/// Dashboard data for specific widget types
#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardWidgetData {
    pub widget_type: String,
    pub data: serde_json::Value,
}

/// Recent scans widget data
#[derive(Debug, Serialize, Deserialize)]
pub struct RecentScansData {
    pub scans: Vec<ScanResult>,
}

/// Vulnerability summary widget data
#[derive(Debug, Serialize, Deserialize)]
pub struct VulnerabilitySummaryData {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

/// Top risky hosts widget data
#[derive(Debug, Serialize, Deserialize)]
pub struct TopRiskyHostsData {
    pub hosts: Vec<RiskyHostInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskyHostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub vulnerability_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub risk_score: f64,
}

/// Upcoming scheduled scans widget data
#[derive(Debug, Serialize, Deserialize)]
pub struct UpcomingScansData {
    pub scans: Vec<ScheduledScan>,
}
