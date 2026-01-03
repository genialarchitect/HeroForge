//! Insider threat detection system (Sprint 8)
//!
//! Provides user behavior analytics for detecting insider threats including:
//! - Activity pattern analysis
//! - Anomaly detection
//! - Risk scoring
//! - Alert generation

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration, Timelike};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub user_id: String,
    pub activity_type: String,
    pub resource: String,
    pub timestamp: DateTime<Utc>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsiderThreatAlert {
    pub id: String,
    pub user_id: String,
    pub alert_type: AlertType,
    pub severity: f32,
    pub description: String,
    pub indicators: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    DataExfiltration,
    PrivilegeEscalation,
    UnusualAccess,
    MassDataAccess,
    PolicyViolation,
}

/// Global state for insider threat tracking
static INSIDER_STATE: once_cell::sync::Lazy<Arc<RwLock<InsiderThreatState>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(InsiderThreatState::default())));

#[derive(Debug, Default)]
struct InsiderThreatState {
    user_baselines: HashMap<String, UserBaseline>,
    user_activities: HashMap<String, Vec<UserActivity>>,
    alerts: Vec<InsiderThreatAlert>,
    risk_scores: HashMap<String, f32>,
}

#[derive(Debug, Clone)]
struct UserBaseline {
    avg_daily_logins: f32,
    avg_files_accessed: f32,
    typical_work_hours: (u32, u32), // Start, end hour
    typical_resources: Vec<String>,
    typical_locations: Vec<String>,
    established_at: DateTime<Utc>,
}

impl Default for UserBaseline {
    fn default() -> Self {
        Self {
            avg_daily_logins: 2.0,
            avg_files_accessed: 50.0,
            typical_work_hours: (8, 18),
            typical_resources: Vec::new(),
            typical_locations: Vec::new(),
            established_at: Utc::now(),
        }
    }
}

/// Analyze user behavior for anomalies
pub async fn analyze_user_behavior(user_id: &str, activities: &[UserActivity]) -> anyhow::Result<Option<InsiderThreatAlert>> {
    if activities.is_empty() {
        return Ok(None);
    }

    let mut state = INSIDER_STATE.write().await;

    // Store activities
    state.user_activities.entry(user_id.to_string())
        .or_insert_with(Vec::new)
        .extend(activities.iter().cloned());

    // Get or create baseline
    let baseline = state.user_baselines.entry(user_id.to_string())
        .or_insert_with(UserBaseline::default)
        .clone();

    // Analyze for various threat patterns
    let mut indicators = Vec::new();
    let mut max_severity: f32 = 0.0;
    let mut detected_type: Option<AlertType> = None;

    // Check for data exfiltration patterns
    if let Some((severity, exfil_indicators)) = detect_data_exfiltration(activities, &baseline) {
        if severity > max_severity {
            max_severity = severity;
            detected_type = Some(AlertType::DataExfiltration);
        }
        indicators.extend(exfil_indicators);
    }

    // Check for unusual access patterns
    if let Some((severity, access_indicators)) = detect_unusual_access(activities, &baseline) {
        if severity > max_severity {
            max_severity = severity;
            detected_type = Some(AlertType::UnusualAccess);
        }
        indicators.extend(access_indicators);
    }

    // Check for mass data access
    if let Some((severity, mass_indicators)) = detect_mass_data_access(activities, &baseline) {
        if severity > max_severity {
            max_severity = severity;
            detected_type = Some(AlertType::MassDataAccess);
        }
        indicators.extend(mass_indicators);
    }

    // Check for privilege escalation
    if let Some((severity, priv_indicators)) = detect_privilege_escalation(activities) {
        if severity > max_severity {
            max_severity = severity;
            detected_type = Some(AlertType::PrivilegeEscalation);
        }
        indicators.extend(priv_indicators);
    }

    // Generate alert if severity threshold met
    if max_severity >= 0.5 && detected_type.is_some() {
        let alert = InsiderThreatAlert {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            alert_type: detected_type.unwrap(),
            severity: max_severity,
            description: format!("Potential insider threat detected for user {}", user_id),
            indicators,
            created_at: Utc::now(),
        };

        state.alerts.push(alert.clone());
        info!("Generated insider threat alert for user {}: severity {}", user_id, max_severity);

        return Ok(Some(alert));
    }

    Ok(None)
}

/// Detect data exfiltration patterns
fn detect_data_exfiltration(activities: &[UserActivity], baseline: &UserBaseline) -> Option<(f32, Vec<String>)> {
    let mut indicators = Vec::new();
    let mut severity: f32 = 0.0;

    // Check for large file downloads/transfers
    let download_activities: Vec<_> = activities.iter()
        .filter(|a| a.activity_type.contains("download") || a.activity_type.contains("transfer"))
        .collect();

    if download_activities.len() > 10 {
        indicators.push(format!("High volume of downloads: {} in session", download_activities.len()));
        severity += 0.3;
    }

    // Check for off-hours data access
    let off_hours: Vec<_> = activities.iter()
        .filter(|a| {
            let hour = a.timestamp.hour();
            hour < baseline.typical_work_hours.0 || hour > baseline.typical_work_hours.1
        })
        .collect();

    if !off_hours.is_empty() {
        indicators.push(format!("{} activities outside normal working hours", off_hours.len()));
        severity += 0.2;
    }

    // Check for access to sensitive resources
    let sensitive_access: Vec<_> = activities.iter()
        .filter(|a| {
            a.resource.contains("confidential") ||
            a.resource.contains("secret") ||
            a.resource.contains("financial") ||
            a.resource.contains("hr") ||
            a.resource.contains("executive")
        })
        .collect();

    if !sensitive_access.is_empty() {
        indicators.push(format!("{} accesses to sensitive resources", sensitive_access.len()));
        severity += 0.3;
    }

    if indicators.is_empty() {
        None
    } else {
        Some((severity.min(1.0), indicators))
    }
}

/// Detect unusual access patterns
fn detect_unusual_access(activities: &[UserActivity], baseline: &UserBaseline) -> Option<(f32, Vec<String>)> {
    let mut indicators = Vec::new();
    let mut severity: f32 = 0.0;

    // Check for access to atypical resources
    let atypical_resources: Vec<_> = activities.iter()
        .filter(|a| !baseline.typical_resources.iter().any(|r| a.resource.contains(r)))
        .collect();

    let atypical_ratio = atypical_resources.len() as f32 / activities.len().max(1) as f32;
    if atypical_ratio > 0.5 && !baseline.typical_resources.is_empty() {
        indicators.push(format!("{:.0}% of activity on atypical resources", atypical_ratio * 100.0));
        severity += 0.4;
    }

    // Check for unusual activity types
    let admin_activities: Vec<_> = activities.iter()
        .filter(|a| {
            a.activity_type.contains("admin") ||
            a.activity_type.contains("config") ||
            a.activity_type.contains("delete")
        })
        .collect();

    if !admin_activities.is_empty() {
        indicators.push(format!("{} administrative actions", admin_activities.len()));
        severity += 0.2;
    }

    // Check for rapid access pattern (many resources in short time)
    if activities.len() > 5 {
        let time_span = activities.last().map(|a| a.timestamp)
            .and_then(|last| activities.first().map(|first| last - first.timestamp));

        if let Some(span) = time_span {
            if span.num_minutes() > 0 {
                let rate = activities.len() as f32 / span.num_minutes() as f32;
                if rate > 10.0 {
                    indicators.push(format!("Rapid resource access: {:.1} per minute", rate));
                    severity += 0.3;
                }
            }
        }
    }

    if indicators.is_empty() {
        None
    } else {
        Some((severity.min(1.0), indicators))
    }
}

/// Detect mass data access
fn detect_mass_data_access(activities: &[UserActivity], baseline: &UserBaseline) -> Option<(f32, Vec<String>)> {
    let mut indicators = Vec::new();
    let mut severity: f32 = 0.0;

    let file_access: Vec<_> = activities.iter()
        .filter(|a| a.activity_type.contains("read") || a.activity_type.contains("access"))
        .collect();

    let access_count = file_access.len() as f32;

    // Compare to baseline
    if access_count > baseline.avg_files_accessed * 3.0 {
        indicators.push(format!(
            "File access {:.0}x above baseline ({} vs {:.0} avg)",
            access_count / baseline.avg_files_accessed,
            access_count as u32,
            baseline.avg_files_accessed
        ));
        severity += 0.5;
    } else if access_count > baseline.avg_files_accessed * 2.0 {
        indicators.push(format!("Elevated file access: {} (2x baseline)", access_count as u32));
        severity += 0.3;
    }

    // Check for enumeration patterns (systematic access)
    let unique_resources: std::collections::HashSet<_> = activities.iter()
        .map(|a| &a.resource)
        .collect();

    if unique_resources.len() > 50 {
        indicators.push(format!("Accessed {} unique resources", unique_resources.len()));
        severity += 0.2;
    }

    if indicators.is_empty() {
        None
    } else {
        Some((severity.min(1.0), indicators))
    }
}

/// Detect privilege escalation attempts
fn detect_privilege_escalation(activities: &[UserActivity]) -> Option<(f32, Vec<String>)> {
    let mut indicators = Vec::new();
    let mut severity: f32 = 0.0;

    // Check for access to admin functions
    let admin_attempts: Vec<_> = activities.iter()
        .filter(|a| {
            a.activity_type.contains("elevate") ||
            a.activity_type.contains("sudo") ||
            a.activity_type.contains("admin") ||
            a.resource.contains("admin") ||
            a.resource.contains("/root") ||
            a.resource.contains("system32")
        })
        .collect();

    if !admin_attempts.is_empty() {
        indicators.push(format!("{} privilege escalation attempts", admin_attempts.len()));
        severity += 0.6;
    }

    // Check for permission changes
    let permission_changes: Vec<_> = activities.iter()
        .filter(|a| {
            a.activity_type.contains("chmod") ||
            a.activity_type.contains("chown") ||
            a.activity_type.contains("permission") ||
            a.activity_type.contains("role")
        })
        .collect();

    if !permission_changes.is_empty() {
        indicators.push(format!("{} permission modification attempts", permission_changes.len()));
        severity += 0.3;
    }

    if indicators.is_empty() {
        None
    } else {
        Some((severity.min(1.0), indicators))
    }
}

/// Calculate overall risk score for user
pub async fn calculate_user_risk_score(user_id: &str) -> anyhow::Result<f32> {
    let state = INSIDER_STATE.read().await;

    let mut score: f32 = 0.0;
    let mut factors = 0;

    // Factor 1: Recent activity risk scores
    if let Some(activities) = state.user_activities.get(user_id) {
        let recent: Vec<_> = activities.iter()
            .filter(|a| a.timestamp > Utc::now() - Duration::days(7))
            .collect();

        if !recent.is_empty() {
            let avg_risk: f32 = recent.iter().map(|a| a.risk_score).sum::<f32>() / recent.len() as f32;
            score += avg_risk;
            factors += 1;
        }
    }

    // Factor 2: Recent alerts
    let user_alerts: Vec<_> = state.alerts.iter()
        .filter(|a| a.user_id == user_id && a.created_at > Utc::now() - Duration::days(30))
        .collect();

    if !user_alerts.is_empty() {
        let alert_score = user_alerts.iter().map(|a| a.severity).sum::<f32>() / user_alerts.len() as f32;
        score += alert_score * 1.5; // Weight alerts higher
        factors += 1;
    }

    // Factor 3: Historical risk score
    if let Some(&historical) = state.risk_scores.get(user_id) {
        score += historical * 0.5; // Weight historical lower
        factors += 1;
    }

    if factors == 0 {
        return Ok(0.0);
    }

    let final_score = (score / factors as f32).min(1.0);

    // Update stored risk score
    drop(state);
    let mut state = INSIDER_STATE.write().await;
    state.risk_scores.insert(user_id.to_string(), final_score);

    Ok(final_score)
}

/// Record user activity
pub async fn record_activity(activity: UserActivity) {
    let mut state = INSIDER_STATE.write().await;
    state.user_activities.entry(activity.user_id.clone())
        .or_insert_with(Vec::new)
        .push(activity);
}

/// Update user baseline
pub async fn update_baseline(user_id: &str, activities: &[UserActivity]) {
    if activities.is_empty() {
        return;
    }

    let mut state = INSIDER_STATE.write().await;

    // Calculate new baseline from activities
    let unique_resources: std::collections::HashSet<_> = activities.iter()
        .map(|a| a.resource.clone())
        .collect();

    let baseline = UserBaseline {
        avg_daily_logins: 2.0, // Would calculate from login events
        avg_files_accessed: activities.len() as f32 / 30.0, // Assume 30 days of data
        typical_work_hours: (8, 18), // Would calculate from timestamps
        typical_resources: unique_resources.into_iter().take(100).collect(),
        typical_locations: Vec::new(),
        established_at: Utc::now(),
    };

    state.user_baselines.insert(user_id.to_string(), baseline);
    info!("Updated baseline for user {}", user_id);
}

/// Get alerts for a user
pub async fn get_user_alerts(user_id: &str) -> Vec<InsiderThreatAlert> {
    let state = INSIDER_STATE.read().await;
    state.alerts.iter()
        .filter(|a| a.user_id == user_id)
        .cloned()
        .collect()
}

/// Get all high-risk users
pub async fn get_high_risk_users() -> Vec<(String, f32)> {
    let state = INSIDER_STATE.read().await;
    let mut users: Vec<_> = state.risk_scores.iter()
        .filter(|(_, &score)| score >= 0.7)
        .map(|(id, &score)| (id.clone(), score))
        .collect();

    users.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    users
}

/// Get insider threat statistics
pub async fn get_statistics() -> InsiderThreatStats {
    let state = INSIDER_STATE.read().await;

    let alerts_by_type: HashMap<String, usize> = state.alerts.iter()
        .fold(HashMap::new(), |mut acc, alert| {
            let type_str = format!("{:?}", alert.alert_type);
            *acc.entry(type_str).or_insert(0) += 1;
            acc
        });

    let high_risk_count = state.risk_scores.values().filter(|&&s| s >= 0.7).count();
    let medium_risk_count = state.risk_scores.values().filter(|&&s| s >= 0.4 && s < 0.7).count();

    InsiderThreatStats {
        total_users_monitored: state.user_activities.len(),
        total_alerts: state.alerts.len(),
        alerts_by_type,
        high_risk_users: high_risk_count,
        medium_risk_users: medium_risk_count,
        avg_risk_score: if state.risk_scores.is_empty() {
            0.0
        } else {
            state.risk_scores.values().sum::<f32>() / state.risk_scores.len() as f32
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsiderThreatStats {
    pub total_users_monitored: usize,
    pub total_alerts: usize,
    pub alerts_by_type: HashMap<String, usize>,
    pub high_risk_users: usize,
    pub medium_risk_users: usize,
    pub avg_risk_score: f32,
}
