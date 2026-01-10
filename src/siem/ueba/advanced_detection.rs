//! Advanced Behavioral Detection Module for UEBA
//!
//! This module implements sophisticated behavioral detection algorithms including:
//! - Enhanced impossible travel detection with VPN/proxy awareness
//! - Unusual data access pattern detection
//! - Off-hours activity with configurable business hours
//! - Service account abuse detection
//! - Lateral movement detection
//! - Data exfiltration detection
//!
//! Each detector uses a combination of baseline analysis, peer group comparison,
//! and rule-based heuristics to identify anomalous behavior.

use anyhow::Result;
use chrono::{DateTime, Datelike, Duration, NaiveTime, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use std::collections::HashSet;
use uuid::Uuid;

use super::types::*;

// ============================================================================
// Configuration Types
// ============================================================================

/// Business hours configuration for an organization or entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct BusinessHoursConfig {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    /// JSON array of working days (0=Sunday, 1=Monday, etc.)
    pub working_days: String,
    /// Start time in HH:MM format
    pub start_time: String,
    /// End time in HH:MM format
    pub end_time: String,
    /// Timezone (e.g., "America/New_York")
    pub timezone: String,
    /// Entity IDs or peer groups this applies to (JSON array, empty = all)
    pub applies_to: Option<String>,
    /// Allow some grace period in minutes
    pub grace_period_minutes: i32,
    pub is_default: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create business hours config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBusinessHoursRequest {
    pub name: String,
    pub description: Option<String>,
    pub working_days: Vec<u8>,
    pub start_time: String,
    pub end_time: String,
    pub timezone: String,
    pub applies_to: Option<Vec<String>>,
    pub grace_period_minutes: Option<i32>,
    pub is_default: Option<bool>,
}

/// Data sensitivity classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

impl DataSensitivity {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataSensitivity::Public => "public",
            DataSensitivity::Internal => "internal",
            DataSensitivity::Confidential => "confidential",
            DataSensitivity::Restricted => "restricted",
            DataSensitivity::TopSecret => "top_secret",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "public" => DataSensitivity::Public,
            "internal" => DataSensitivity::Internal,
            "confidential" => DataSensitivity::Confidential,
            "restricted" => DataSensitivity::Restricted,
            "top_secret" => DataSensitivity::TopSecret,
            _ => DataSensitivity::Internal,
        }
    }

    /// Risk multiplier based on sensitivity
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            DataSensitivity::Public => 0.5,
            DataSensitivity::Internal => 1.0,
            DataSensitivity::Confidential => 2.0,
            DataSensitivity::Restricted => 3.0,
            DataSensitivity::TopSecret => 5.0,
        }
    }
}

/// Sensitive resource definition
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SensitiveResource {
    pub id: String,
    pub user_id: String,
    pub resource_type: String,
    pub resource_pattern: String,
    pub sensitivity: String,
    pub description: Option<String>,
    pub allowed_entities: Option<String>,
    pub alert_on_access: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Data access record for tracking
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DataAccessRecord {
    pub id: String,
    pub entity_id: String,
    pub resource_id: Option<String>,
    pub resource_type: String,
    pub resource_path: String,
    pub access_type: String,
    pub sensitivity: String,
    pub bytes_accessed: Option<i64>,
    pub is_first_access: bool,
    pub is_unusual: bool,
    pub timestamp: String,
    pub created_at: String,
}

/// Host access record for lateral movement detection
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HostAccessRecord {
    pub id: String,
    pub entity_id: String,
    pub source_host: String,
    pub destination_host: String,
    pub access_type: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub is_successful: bool,
    pub timestamp: String,
    pub created_at: String,
}

/// Data transfer record for exfiltration detection
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DataTransferRecord {
    pub id: String,
    pub entity_id: String,
    pub transfer_type: String,
    pub source: String,
    pub destination: String,
    pub destination_type: String,
    pub bytes_transferred: i64,
    pub file_count: Option<i32>,
    pub file_types: Option<String>,
    pub is_encrypted: bool,
    pub is_external: bool,
    pub timestamp: String,
    pub created_at: String,
}

// ============================================================================
// Advanced Detection Engine
// ============================================================================

/// Configuration for advanced detection
#[derive(Debug, Clone)]
pub struct AdvancedDetectionConfig {
    // Impossible travel
    pub max_travel_speed_kmh: f64,
    pub min_distance_km: f64,
    pub ignore_vpn: bool,

    // Off-hours
    pub off_hours_severity: String,
    pub weekend_multiplier: f64,
    pub holiday_multiplier: f64,

    // Data access
    pub unusual_resource_threshold: i32,
    pub sensitive_access_alert: bool,
    pub first_access_window_days: i32,

    // Service account
    pub service_account_interactive_alert: bool,
    pub service_account_off_hours_alert: bool,
    pub service_account_new_host_alert: bool,

    // Lateral movement
    pub lateral_movement_window_minutes: i32,
    pub lateral_movement_host_threshold: i32,
    pub lateral_movement_use_graph: bool,

    // Data exfiltration
    pub exfiltration_threshold_mb: f64,
    pub exfiltration_window_hours: i32,
    pub external_upload_alert: bool,
    pub sensitive_file_types: Vec<String>,
}

impl Default for AdvancedDetectionConfig {
    fn default() -> Self {
        Self {
            // Impossible travel
            max_travel_speed_kmh: 900.0,
            min_distance_km: 100.0,
            ignore_vpn: false,

            // Off-hours
            off_hours_severity: "low".to_string(),
            weekend_multiplier: 1.5,
            holiday_multiplier: 2.0,

            // Data access
            unusual_resource_threshold: 3,
            sensitive_access_alert: true,
            first_access_window_days: 30,

            // Service account
            service_account_interactive_alert: true,
            service_account_off_hours_alert: true,
            service_account_new_host_alert: true,

            // Lateral movement
            lateral_movement_window_minutes: 60,
            lateral_movement_host_threshold: 5,
            lateral_movement_use_graph: true,

            // Data exfiltration
            exfiltration_threshold_mb: 100.0,
            exfiltration_window_hours: 24,
            external_upload_alert: true,
            sensitive_file_types: vec![
                "xlsx".to_string(), "docx".to_string(), "pdf".to_string(),
                "csv".to_string(), "sql".to_string(), "zip".to_string(),
                "7z".to_string(), "rar".to_string(), "pst".to_string(),
            ],
        }
    }
}

/// Advanced behavioral detection engine
pub struct AdvancedDetectionEngine {
    pool: SqlitePool,
    config: AdvancedDetectionConfig,
}

impl AdvancedDetectionEngine {
    /// Create new engine with default config
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            config: AdvancedDetectionConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(pool: SqlitePool, config: AdvancedDetectionConfig) -> Self {
        Self { pool, config }
    }

    // ========================================================================
    // Impossible Travel Detection (Enhanced)
    // ========================================================================

    /// Enhanced impossible travel detection with VPN awareness and confidence scoring
    pub async fn detect_impossible_travel(
        &self,
        entity: &UebaEntity,
        current_location: &GeoLocation,
        current_time: &DateTime<Utc>,
        is_vpn: bool,
        is_proxy: bool,
    ) -> Result<Option<ImpossibleTravelResult>> {
        // Skip if VPN and configured to ignore
        if is_vpn && self.config.ignore_vpn {
            return Ok(None);
        }

        // Get previous location-based activity
        let previous: Option<(f64, f64, String, String, bool, bool)> = sqlx::query_as(
            r#"
            SELECT source_lat, source_lon, source_country, started_at, is_vpn, is_proxy
            FROM ueba_sessions
            WHERE entity_id = ?
            AND source_lat IS NOT NULL
            AND source_lon IS NOT NULL
            AND started_at < ?
            ORDER BY started_at DESC
            LIMIT 1
            "#,
        )
        .bind(&entity.id)
        .bind(current_time.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;

        let (prev_lat, prev_lon, prev_country, prev_time_str, prev_vpn, prev_proxy) =
            match previous {
                Some(p) => p,
                None => return Ok(None),
            };

        let prev_location = GeoLocation {
            lat: prev_lat,
            lon: prev_lon,
            country: Some(prev_country.clone()),
            city: None,
        };

        let prev_time = DateTime::parse_from_rfc3339(&prev_time_str)?
            .with_timezone(&Utc);

        let time_diff_hours = (*current_time - prev_time).num_minutes() as f64 / 60.0;

        if time_diff_hours <= 0.0 {
            return Ok(None);
        }

        let distance_km = current_location.distance_km(&prev_location);

        // Skip if distance is too small
        if distance_km < self.config.min_distance_km {
            return Ok(None);
        }

        let required_speed = distance_km / time_diff_hours;

        if required_speed > self.config.max_travel_speed_kmh {
            // Calculate confidence based on factors
            let mut confidence: f64 = 0.95;

            // Lower confidence if VPN/proxy involved
            if is_vpn || prev_vpn {
                confidence -= 0.2;
            }
            if is_proxy || prev_proxy {
                confidence -= 0.15;
            }

            // Same country might be VPN
            if current_location.country == Some(prev_country.clone()) {
                confidence -= 0.1;
            }

            confidence = confidence.max(0.3);

            let severity = if required_speed > self.config.max_travel_speed_kmh * 10.0 {
                "critical"
            } else if required_speed > self.config.max_travel_speed_kmh * 3.0 {
                "high"
            } else {
                "medium"
            };

            return Ok(Some(ImpossibleTravelResult {
                previous_location: prev_location,
                current_location: current_location.clone(),
                previous_time: prev_time,
                current_time: *current_time,
                distance_km,
                time_diff_hours,
                required_speed_kmh: required_speed,
                max_allowed_speed_kmh: self.config.max_travel_speed_kmh,
                confidence,
                severity: severity.to_string(),
                is_vpn_involved: is_vpn || prev_vpn,
                is_proxy_involved: is_proxy || prev_proxy,
            }));
        }

        Ok(None)
    }

    // ========================================================================
    // Off-Hours Activity Detection
    // ========================================================================

    /// Detect off-hours activity with configurable business hours
    pub async fn detect_off_hours_activity(
        &self,
        user_id: &str,
        entity: &UebaEntity,
        timestamp: &DateTime<Utc>,
    ) -> Result<Option<OffHoursResult>> {
        // Get applicable business hours config
        let config = self.get_business_hours_config(user_id, &entity.id).await?;

        let (working_days, start_time, end_time, grace_minutes) = match config {
            Some(c) => {
                let days: Vec<u8> = serde_json::from_str(&c.working_days).unwrap_or_default();
                let start = NaiveTime::parse_from_str(&c.start_time, "%H:%M")
                    .unwrap_or(NaiveTime::from_hms_opt(8, 0, 0).unwrap());
                let end = NaiveTime::parse_from_str(&c.end_time, "%H:%M")
                    .unwrap_or(NaiveTime::from_hms_opt(18, 0, 0).unwrap());
                (days, start, end, c.grace_period_minutes)
            }
            None => {
                // Default: Mon-Fri, 8am-6pm
                (vec![1, 2, 3, 4, 5],
                 NaiveTime::from_hms_opt(8, 0, 0).unwrap(),
                 NaiveTime::from_hms_opt(18, 0, 0).unwrap(),
                 15)
            }
        };

        let weekday = timestamp.weekday().num_days_from_sunday() as u8;
        let time = timestamp.time();

        // Check if working day
        let is_working_day = working_days.contains(&weekday);

        // Check if within working hours (with grace period)
        let start_with_grace = start_time - chrono::Duration::minutes(grace_minutes as i64);
        let end_with_grace = end_time + chrono::Duration::minutes(grace_minutes as i64);
        let is_working_hours = time >= start_with_grace && time <= end_with_grace;

        let is_off_hours = !is_working_day || !is_working_hours;

        if !is_off_hours {
            return Ok(None);
        }

        // Check if entity typically has off-hours activity
        let off_hours_baseline = self.get_off_hours_baseline(&entity.id).await?;

        // If entity normally works off-hours (>30% of activity), lower severity
        let typical_off_hours = off_hours_baseline.unwrap_or(0.0) > 0.3;

        let is_weekend = matches!(timestamp.weekday(), Weekday::Sat | Weekday::Sun);

        let mut severity = self.config.off_hours_severity.clone();
        let mut risk_multiplier = 1.0;

        if is_weekend {
            risk_multiplier = self.config.weekend_multiplier;
            severity = "medium".to_string();
        }

        // Check for holiday
        let is_holiday = self.is_holiday(user_id, timestamp).await.unwrap_or(false);
        if is_holiday {
            risk_multiplier *= self.config.weekend_multiplier;
            severity = "medium".to_string();
        }

        if typical_off_hours {
            severity = "low".to_string();
            risk_multiplier *= 0.5;
        }

        // Service accounts get higher severity
        if entity.is_service_account {
            severity = "high".to_string();
            risk_multiplier *= 2.0;
        }

        Ok(Some(OffHoursResult {
            timestamp: *timestamp,
            working_hours_start: start_time,
            working_hours_end: end_time,
            working_days: working_days.clone(),
            is_weekend,
            is_holiday,
            typical_off_hours_rate: off_hours_baseline.unwrap_or(0.0),
            severity,
            risk_multiplier,
            is_service_account: entity.is_service_account,
        }))
    }

    // ========================================================================
    // Unusual Data Access Detection
    // ========================================================================

    /// Detect unusual data access patterns
    pub async fn detect_unusual_data_access(
        &self,
        user_id: &str,
        entity: &UebaEntity,
        resource_type: &str,
        resource_path: &str,
        access_type: &str,
        bytes_accessed: Option<i64>,
    ) -> Result<Option<UnusualDataAccessResult>> {
        let mut anomalies: Vec<DataAccessAnomaly> = Vec::new();
        let mut risk_score = 0;

        // Check if this is a first-time access
        let first_access = self.is_first_time_access(&entity.id, resource_path).await?;

        if first_access {
            anomalies.push(DataAccessAnomaly::FirstTimeAccess);
            risk_score += 10;
        }

        // Check resource sensitivity
        let sensitivity = self.get_resource_sensitivity(user_id, resource_type, resource_path).await?;

        if let Some(ref sens) = sensitivity {
            let sens_level = DataSensitivity::from_str(sens);
            risk_score = (risk_score as f64 * sens_level.risk_multiplier()) as i32;

            if self.config.sensitive_access_alert &&
               matches!(sens_level, DataSensitivity::Confidential | DataSensitivity::Restricted | DataSensitivity::TopSecret) {
                anomalies.push(DataAccessAnomaly::SensitiveDataAccess(sens.clone()));
            }
        }

        // Check peer group comparison
        let peer_comparison = self.compare_data_access_to_peers(&entity.id, resource_type, resource_path).await?;

        if peer_comparison.is_some_and(|p| p.deviation_score > 1.5) {
            anomalies.push(DataAccessAnomaly::PeerGroupDeviation);
            risk_score += 15;
        }

        // Check for unusual volume
        if let Some(bytes) = bytes_accessed {
            let volume_baseline = self.get_data_volume_baseline(&entity.id, access_type).await?;
            if let Some((mean, std_dev)) = volume_baseline {
                if std_dev > 0.0 {
                    let deviation = (bytes as f64 - mean) / std_dev;
                    if deviation > 3.0 {
                        anomalies.push(DataAccessAnomaly::UnusualVolume {
                            bytes_accessed: bytes,
                            baseline_mean: mean,
                            deviation,
                        });
                        risk_score += 20;
                    }
                }
            }
        }

        // Check for access to new resource category
        let accessed_categories = self.get_entity_resource_categories(&entity.id).await?;
        let current_category = self.categorize_resource(resource_type, resource_path);

        if !accessed_categories.contains(&current_category) {
            anomalies.push(DataAccessAnomaly::NewResourceCategory(current_category));
            risk_score += 10;
        }

        if anomalies.is_empty() {
            return Ok(None);
        }

        let severity = if risk_score >= 40 {
            "high"
        } else if risk_score >= 20 {
            "medium"
        } else {
            "low"
        };

        Ok(Some(UnusualDataAccessResult {
            entity_id: entity.id.clone(),
            resource_type: resource_type.to_string(),
            resource_path: resource_path.to_string(),
            access_type: access_type.to_string(),
            is_first_access: first_access,
            sensitivity,
            anomalies,
            risk_score,
            severity: severity.to_string(),
            timestamp: Utc::now(),
        }))
    }

    // ========================================================================
    // Service Account Abuse Detection
    // ========================================================================

    /// Detect service account abuse
    pub async fn detect_service_account_abuse(
        &self,
        user_id: &str,
        entity: &UebaEntity,
        activity_type: &str,
        source_ip: Option<&str>,
        is_interactive: bool,
    ) -> Result<Option<ServiceAccountAbuseResult>> {
        if !entity.is_service_account {
            return Ok(None);
        }

        let mut abuse_indicators: Vec<ServiceAccountAbuseIndicator> = Vec::new();
        let mut risk_score = 0;

        // Check for interactive login
        if is_interactive && self.config.service_account_interactive_alert {
            abuse_indicators.push(ServiceAccountAbuseIndicator::InteractiveLogin);
            risk_score += 30;
        }

        // Check for off-hours activity
        if self.config.service_account_off_hours_alert {
            let off_hours = self.detect_off_hours_activity(user_id, entity, &Utc::now()).await?;
            if off_hours.is_some() {
                abuse_indicators.push(ServiceAccountAbuseIndicator::OffHoursActivity);
                risk_score += 25;
            }
        }

        // Check for new source host
        if let Some(ip) = source_ip {
            let known_hosts = self.get_service_account_known_hosts(&entity.id).await?;
            if !known_hosts.contains(&ip.to_string()) && self.config.service_account_new_host_alert {
                abuse_indicators.push(ServiceAccountAbuseIndicator::NewSourceHost(ip.to_string()));
                risk_score += 20;
            }
        }

        // Check for unusual activity type
        let normal_activities = self.get_service_account_normal_activities(&entity.id).await?;
        if !normal_activities.contains(&activity_type.to_string()) {
            abuse_indicators.push(ServiceAccountAbuseIndicator::UnusualActivityType(activity_type.to_string()));
            risk_score += 15;
        }

        // Check for privilege escalation attempts
        if activity_type == "privilege_escalation" || activity_type == "admin_action" {
            abuse_indicators.push(ServiceAccountAbuseIndicator::PrivilegeEscalation);
            risk_score += 35;
        }

        // Check for rapid activity burst
        let recent_activity_count = self.get_recent_activity_count(&entity.id, 5).await?;
        if recent_activity_count > 50 {
            abuse_indicators.push(ServiceAccountAbuseIndicator::RapidActivityBurst(recent_activity_count));
            risk_score += 20;
        }

        if abuse_indicators.is_empty() {
            return Ok(None);
        }

        let severity = if risk_score >= 50 {
            "critical"
        } else if risk_score >= 30 {
            "high"
        } else {
            "medium"
        };

        Ok(Some(ServiceAccountAbuseResult {
            entity_id: entity.id.clone(),
            service_account_name: entity.display_name.clone().unwrap_or_else(|| entity.entity_id.clone()),
            indicators: abuse_indicators,
            risk_score,
            severity: severity.to_string(),
            mitre_techniques: vec!["T1078.002".to_string()],
            timestamp: Utc::now(),
        }))
    }

    // ========================================================================
    // Lateral Movement Detection
    // ========================================================================

    /// Detect lateral movement patterns
    pub async fn detect_lateral_movement(
        &self,
        entity: &UebaEntity,
        destination_host: &str,
        access_type: &str,
    ) -> Result<Option<LateralMovementResult>> {
        let window = Utc::now() - Duration::minutes(self.config.lateral_movement_window_minutes as i64);

        // Get recent host accesses
        let recent_hosts: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT destination_host, access_type, timestamp
            FROM ueba_host_accesses
            WHERE entity_id = ?
            AND timestamp >= ?
            ORDER BY timestamp ASC
            "#,
        )
        .bind(&entity.id)
        .bind(window.to_rfc3339())
        .fetch_all(&self.pool)
        .await?;

        // Build access chain
        let mut unique_hosts: HashSet<String> = HashSet::new();
        let mut access_chain: Vec<HostAccess> = Vec::new();

        for (host, acc_type, ts) in &recent_hosts {
            unique_hosts.insert(host.clone());
            access_chain.push(HostAccess {
                host: host.clone(),
                access_type: acc_type.clone(),
                timestamp: ts.clone(),
            });
        }

        // Add current access
        unique_hosts.insert(destination_host.to_string());
        access_chain.push(HostAccess {
            host: destination_host.to_string(),
            access_type: access_type.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        });

        let unique_host_count = unique_hosts.len();

        if unique_host_count < self.config.lateral_movement_host_threshold as usize {
            return Ok(None);
        }

        // Calculate velocity (hosts per hour)
        let time_range_hours = self.config.lateral_movement_window_minutes as f64 / 60.0;
        let velocity = unique_host_count as f64 / time_range_hours;

        // Check for suspicious patterns
        let mut patterns: Vec<LateralMovementPattern> = Vec::new();

        // Sequential access pattern (A -> B -> C)
        if access_chain.len() >= 3 {
            patterns.push(LateralMovementPattern::SequentialHopping);
        }

        // Check for admin tool usage
        let admin_access_types = ["rdp", "ssh", "psexec", "wmi", "winrm"];
        let admin_tools_used: Vec<String> = access_chain
            .iter()
            .filter(|a| admin_access_types.contains(&a.access_type.to_lowercase().as_str()))
            .map(|a| a.access_type.clone())
            .collect();

        if !admin_tools_used.is_empty() {
            patterns.push(LateralMovementPattern::AdminToolUsage(admin_tools_used.clone()));
        }

        // Check for credential usage across hosts
        // This would need additional data about auth methods used

        let severity = if unique_host_count >= 10 {
            "critical"
        } else if unique_host_count >= 7 {
            "high"
        } else {
            "medium"
        };

        let risk_score = (unique_host_count * 10).min(100) as i32;

        Ok(Some(LateralMovementResult {
            entity_id: entity.id.clone(),
            unique_hosts: unique_hosts.into_iter().collect(),
            access_chain,
            time_window_minutes: self.config.lateral_movement_window_minutes,
            velocity_hosts_per_hour: velocity,
            patterns,
            risk_score,
            severity: severity.to_string(),
            mitre_techniques: vec!["T1021".to_string(), "T1563".to_string()],
            timestamp: Utc::now(),
        }))
    }

    // ========================================================================
    // Data Exfiltration Detection
    // ========================================================================

    /// Detect potential data exfiltration
    pub async fn detect_data_exfiltration(
        &self,
        entity: &UebaEntity,
        destination: &str,
        destination_type: &str,
        bytes_transferred: i64,
        file_count: Option<i32>,
        file_types: Option<&[String]>,
        is_encrypted: bool,
    ) -> Result<Option<DataExfiltrationResult>> {
        let mut indicators: Vec<ExfiltrationIndicator> = Vec::new();
        let mut risk_score = 0;

        let bytes_mb = bytes_transferred as f64 / (1024.0 * 1024.0);

        // Check transfer volume
        if bytes_mb >= self.config.exfiltration_threshold_mb {
            indicators.push(ExfiltrationIndicator::LargeVolume {
                bytes_transferred,
                threshold_mb: self.config.exfiltration_threshold_mb,
            });
            risk_score += 30;
        }

        // Check for external destination
        let is_external = self.is_external_destination(destination, destination_type);
        if is_external && self.config.external_upload_alert {
            indicators.push(ExfiltrationIndicator::ExternalDestination(destination.to_string()));
            risk_score += 25;
        }

        // Check for sensitive file types
        if let Some(types) = file_types {
            let sensitive_types: Vec<String> = types
                .iter()
                .filter(|t| self.config.sensitive_file_types.contains(t))
                .cloned()
                .collect();

            if !sensitive_types.is_empty() {
                indicators.push(ExfiltrationIndicator::SensitiveFileTypes(sensitive_types));
                risk_score += 20;
            }
        }

        // Check for compression/encryption
        if is_encrypted {
            indicators.push(ExfiltrationIndicator::EncryptedTransfer);
            risk_score += 15;
        }

        // Check timing (off-hours exfiltration is more suspicious)
        let now = Utc::now();
        let hour = now.hour();
        if hour < 6 || hour > 22 {
            indicators.push(ExfiltrationIndicator::OffHoursTiming);
            risk_score += 10;
        }

        // Check cumulative transfer in window
        let window = now - Duration::hours(self.config.exfiltration_window_hours as i64);
        let cumulative: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COALESCE(SUM(bytes_transferred), 0)
            FROM ueba_data_transfers
            WHERE entity_id = ?
            AND is_external = TRUE
            AND timestamp >= ?
            "#,
        )
        .bind(&entity.id)
        .bind(window.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;

        let cumulative_bytes = cumulative.map(|c| c.0).unwrap_or(0) + bytes_transferred;
        let cumulative_mb = cumulative_bytes as f64 / (1024.0 * 1024.0);

        if cumulative_mb > self.config.exfiltration_threshold_mb * 2.0 {
            indicators.push(ExfiltrationIndicator::CumulativeVolumeExceeded {
                cumulative_mb,
                window_hours: self.config.exfiltration_window_hours,
            });
            risk_score += 25;
        }

        // Check for unusual destination
        let known_destinations = self.get_entity_known_destinations(&entity.id).await?;
        if !known_destinations.contains(&destination.to_string()) {
            indicators.push(ExfiltrationIndicator::NewDestination(destination.to_string()));
            risk_score += 15;
        }

        if indicators.is_empty() {
            return Ok(None);
        }

        let severity = if risk_score >= 60 {
            "critical"
        } else if risk_score >= 40 {
            "high"
        } else if risk_score >= 20 {
            "medium"
        } else {
            "low"
        };

        Ok(Some(DataExfiltrationResult {
            entity_id: entity.id.clone(),
            destination: destination.to_string(),
            destination_type: destination_type.to_string(),
            bytes_transferred,
            file_count,
            indicators,
            cumulative_bytes_in_window: cumulative_bytes,
            is_external,
            risk_score,
            severity: severity.to_string(),
            mitre_techniques: vec!["T1041".to_string(), "T1048".to_string(), "T1567".to_string()],
            timestamp: Utc::now(),
        }))
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    async fn get_business_hours_config(&self, user_id: &str, entity_id: &str) -> Result<Option<BusinessHoursConfig>> {
        // First try entity-specific config
        let config: Option<BusinessHoursConfig> = sqlx::query_as(
            r#"
            SELECT * FROM ueba_business_hours
            WHERE user_id = ?
            AND (applies_to IS NULL OR applies_to LIKE ?)
            ORDER BY is_default ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(format!("%{}%", entity_id))
        .fetch_optional(&self.pool)
        .await?;

        Ok(config)
    }

    async fn get_off_hours_baseline(&self, entity_id: &str) -> Result<Option<f64>> {
        let baseline: Option<(Option<f64>,)> = sqlx::query_as(
            r#"
            SELECT mean_value FROM ueba_baselines
            WHERE entity_id = ?
            AND metric_name = 'off_hours_activity_rate'
            "#,
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(baseline.and_then(|b| b.0))
    }

    /// Check if a given timestamp falls on a holiday for the user's organization
    async fn is_holiday(&self, user_id: &str, timestamp: &DateTime<Utc>) -> Result<bool> {
        // Format the date as YYYY-MM-DD for comparison
        let date_str = timestamp.format("%Y-%m-%d").to_string();

        // Check for exact date match in organization holidays
        let holiday: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT 1 FROM organization_holidays
            WHERE user_id = ?
            AND date = ?
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(&date_str)
        .fetch_optional(&self.pool)
        .await?;

        if holiday.is_some() {
            return Ok(true);
        }

        // Check for recurring holidays (month-day match regardless of year)
        let month_day = timestamp.format("%m-%d").to_string();
        let recurring: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT 1 FROM organization_holidays
            WHERE user_id = ?
            AND is_recurring = TRUE
            AND strftime('%m-%d', date) = ?
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(&month_day)
        .fetch_optional(&self.pool)
        .await?;

        Ok(recurring.is_some())
    }

    async fn is_first_time_access(&self, entity_id: &str, resource_path: &str) -> Result<bool> {
        let existing: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_data_accesses
            WHERE entity_id = ?
            AND resource_path = ?
            "#,
        )
        .bind(entity_id)
        .bind(resource_path)
        .fetch_optional(&self.pool)
        .await?;

        Ok(existing.map(|c| c.0 == 0).unwrap_or(true))
    }

    async fn get_resource_sensitivity(&self, user_id: &str, resource_type: &str, resource_path: &str) -> Result<Option<String>> {
        let sensitivity: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT sensitivity FROM ueba_sensitive_resources
            WHERE user_id = ?
            AND resource_type = ?
            AND (resource_path = ? OR ? LIKE resource_pattern)
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(resource_type)
        .bind(resource_path)
        .bind(resource_path)
        .fetch_optional(&self.pool)
        .await?;

        Ok(sensitivity.map(|s| s.0))
    }

    async fn compare_data_access_to_peers(&self, entity_id: &str, resource_type: &str, resource_path: &str) -> Result<Option<PeerComparison>> {
        // Get entity's peer group
        let entity: Option<UebaEntity> = sqlx::query_as(
            "SELECT * FROM ueba_entities WHERE id = ?"
        )
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        let peer_group_id = match entity.and_then(|e| e.peer_group_id) {
            Some(id) => id,
            None => return Ok(None),
        };

        // Get peer group member IDs (excluding the current entity)
        let peer_ids: Vec<(String,)> = sqlx::query_as(
            r#"SELECT id FROM ueba_entities
               WHERE peer_group_id = ? AND id != ?"#
        )
        .bind(&peer_group_id)
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        if peer_ids.is_empty() {
            return Ok(None);
        }

        let peer_count = peer_ids.len() as i64;

        // Count how many peers have accessed this specific resource
        let peers_with_access: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(DISTINCT entity_id) FROM ueba_data_accesses
               WHERE entity_id IN (SELECT id FROM ueba_entities WHERE peer_group_id = ? AND id != ?)
               AND resource_type = ?
               AND resource_path = ?"#
        )
        .bind(&peer_group_id)
        .bind(entity_id)
        .bind(resource_type)
        .bind(resource_path)
        .fetch_one(&self.pool)
        .await?;

        // Calculate peer percentage
        let peer_percentage = if peer_count > 0 {
            (peers_with_access.0 as f64 / peer_count as f64) * 100.0
        } else {
            0.0
        };

        // Get average access count for this resource among peers
        let avg_access: Option<(Option<f64>,)> = sqlx::query_as(
            r#"SELECT AVG(access_count) FROM (
                SELECT COUNT(*) as access_count FROM ueba_data_accesses
                WHERE entity_id IN (SELECT id FROM ueba_entities WHERE peer_group_id = ? AND id != ?)
                AND resource_type = ?
                AND resource_path = ?
                GROUP BY entity_id
            )"#
        )
        .bind(&peer_group_id)
        .bind(entity_id)
        .bind(resource_type)
        .bind(resource_path)
        .fetch_optional(&self.pool)
        .await?;

        let avg_peer_access = avg_access.and_then(|a| a.0).unwrap_or(0.0);

        // Calculate how unusual this access is (lower percentage = more unusual)
        let deviation_score = if peer_percentage < 10.0 {
            2.0  // Very unusual - less than 10% of peers access this
        } else if peer_percentage < 30.0 {
            1.5  // Somewhat unusual
        } else if peer_percentage < 50.0 {
            1.2  // Slightly unusual
        } else {
            1.0  // Normal
        };

        Ok(Some(PeerComparison {
            peer_group_id,
            peer_count,
            peers_with_access: peers_with_access.0,
            peer_percentage,
            avg_peer_access,
            deviation_score,
        }))
    }

    async fn get_data_volume_baseline(&self, entity_id: &str, access_type: &str) -> Result<Option<(f64, f64)>> {
        let baseline: Option<(Option<f64>, Option<f64>)> = sqlx::query_as(
            r#"
            SELECT mean_value, std_deviation FROM ueba_baselines
            WHERE entity_id = ?
            AND metric_name = ?
            AND is_stable = TRUE
            "#,
        )
        .bind(entity_id)
        .bind(format!("{}_bytes", access_type))
        .fetch_optional(&self.pool)
        .await?;

        Ok(baseline.and_then(|b| match (b.0, b.1) {
            (Some(mean), Some(std)) => Some((mean, std)),
            _ => None,
        }))
    }

    async fn get_entity_resource_categories(&self, entity_id: &str) -> Result<HashSet<String>> {
        let categories: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT resource_type FROM ueba_data_accesses
            WHERE entity_id = ?
            "#,
        )
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(categories.into_iter().map(|c| c.0).collect())
    }

    fn categorize_resource(&self, resource_type: &str, _resource_path: &str) -> String {
        resource_type.to_string()
    }

    async fn get_service_account_known_hosts(&self, entity_id: &str) -> Result<HashSet<String>> {
        let hosts: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT source_ip FROM ueba_sessions
            WHERE entity_id = ?
            AND source_ip IS NOT NULL
            "#,
        )
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(hosts.into_iter().map(|h| h.0).collect())
    }

    async fn get_service_account_normal_activities(&self, entity_id: &str) -> Result<HashSet<String>> {
        let activities: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT activity_type FROM ueba_activities
            WHERE entity_id = ?
            ORDER BY COUNT(*) DESC
            LIMIT 10
            "#,
        )
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(activities.into_iter().map(|a| a.0).collect())
    }

    async fn get_recent_activity_count(&self, entity_id: &str, window_minutes: i32) -> Result<i64> {
        let window = Utc::now() - Duration::minutes(window_minutes as i64);

        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_activities
            WHERE entity_id = ?
            AND timestamp >= ?
            "#,
        )
        .bind(entity_id)
        .bind(window.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }

    fn is_external_destination(&self, destination: &str, destination_type: &str) -> bool {
        let external_types = ["cloud_storage", "external_email", "file_sharing", "personal_storage"];

        if external_types.contains(&destination_type) {
            return true;
        }

        // Check for known external domains
        let external_domains = ["dropbox.com", "drive.google.com", "onedrive.live.com",
                               "box.com", "wetransfer.com", "mega.nz", "pastebin.com"];

        for domain in &external_domains {
            if destination.contains(domain) {
                return true;
            }
        }

        false
    }

    async fn get_entity_known_destinations(&self, entity_id: &str) -> Result<HashSet<String>> {
        let destinations: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT destination FROM ueba_data_transfers
            WHERE entity_id = ?
            "#,
        )
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(destinations.into_iter().map(|d| d.0).collect())
    }

    // ========================================================================
    // Record Functions (for data ingestion)
    // ========================================================================

    /// Record a data access event
    pub async fn record_data_access(
        &self,
        entity_id: &str,
        resource_type: &str,
        resource_path: &str,
        access_type: &str,
        sensitivity: Option<&str>,
        bytes_accessed: Option<i64>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let is_first = self.is_first_time_access(entity_id, resource_path).await?;

        sqlx::query(
            r#"
            INSERT INTO ueba_data_accesses (
                id, entity_id, resource_type, resource_path, access_type,
                sensitivity, bytes_accessed, is_first_access, is_unusual, timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(entity_id)
        .bind(resource_type)
        .bind(resource_path)
        .bind(access_type)
        .bind(sensitivity.unwrap_or("internal"))
        .bind(bytes_accessed)
        .bind(is_first)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Record a host access event
    pub async fn record_host_access(
        &self,
        entity_id: &str,
        source_host: &str,
        destination_host: &str,
        access_type: &str,
        protocol: Option<&str>,
        port: Option<i32>,
        is_successful: bool,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO ueba_host_accesses (
                id, entity_id, source_host, destination_host, access_type,
                protocol, port, is_successful, timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(entity_id)
        .bind(source_host)
        .bind(destination_host)
        .bind(access_type)
        .bind(protocol)
        .bind(port)
        .bind(is_successful)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Record a data transfer event
    pub async fn record_data_transfer(
        &self,
        entity_id: &str,
        transfer_type: &str,
        source: &str,
        destination: &str,
        destination_type: &str,
        bytes_transferred: i64,
        file_count: Option<i32>,
        file_types: Option<&[String]>,
        is_encrypted: bool,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let is_external = self.is_external_destination(destination, destination_type);
        let file_types_json = file_types.map(|ft| serde_json::to_string(ft).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO ueba_data_transfers (
                id, entity_id, transfer_type, source, destination, destination_type,
                bytes_transferred, file_count, file_types, is_encrypted, is_external, timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(entity_id)
        .bind(transfer_type)
        .bind(source)
        .bind(destination)
        .bind(destination_type)
        .bind(bytes_transferred)
        .bind(file_count)
        .bind(&file_types_json)
        .bind(is_encrypted)
        .bind(is_external)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }
}

// ============================================================================
// Result Types
// ============================================================================

/// Result from impossible travel detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpossibleTravelResult {
    pub previous_location: GeoLocation,
    pub current_location: GeoLocation,
    pub previous_time: DateTime<Utc>,
    pub current_time: DateTime<Utc>,
    pub distance_km: f64,
    pub time_diff_hours: f64,
    pub required_speed_kmh: f64,
    pub max_allowed_speed_kmh: f64,
    pub confidence: f64,
    pub severity: String,
    pub is_vpn_involved: bool,
    pub is_proxy_involved: bool,
}

/// Result from off-hours detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffHoursResult {
    pub timestamp: DateTime<Utc>,
    pub working_hours_start: NaiveTime,
    pub working_hours_end: NaiveTime,
    pub working_days: Vec<u8>,
    pub is_weekend: bool,
    pub is_holiday: bool,
    pub typical_off_hours_rate: f64,
    pub severity: String,
    pub risk_multiplier: f64,
    pub is_service_account: bool,
}

/// Unusual data access anomaly types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataAccessAnomaly {
    FirstTimeAccess,
    SensitiveDataAccess(String),
    PeerGroupDeviation,
    UnusualVolume {
        bytes_accessed: i64,
        baseline_mean: f64,
        deviation: f64,
    },
    NewResourceCategory(String),
}

/// Result from unusual data access detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusualDataAccessResult {
    pub entity_id: String,
    pub resource_type: String,
    pub resource_path: String,
    pub access_type: String,
    pub is_first_access: bool,
    pub sensitivity: Option<String>,
    pub anomalies: Vec<DataAccessAnomaly>,
    pub risk_score: i32,
    pub severity: String,
    pub timestamp: DateTime<Utc>,
}

/// Service account abuse indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceAccountAbuseIndicator {
    InteractiveLogin,
    OffHoursActivity,
    NewSourceHost(String),
    UnusualActivityType(String),
    PrivilegeEscalation,
    RapidActivityBurst(i64),
}

/// Result from service account abuse detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountAbuseResult {
    pub entity_id: String,
    pub service_account_name: String,
    pub indicators: Vec<ServiceAccountAbuseIndicator>,
    pub risk_score: i32,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Host access record for lateral movement chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAccess {
    pub host: String,
    pub access_type: String,
    pub timestamp: String,
}

/// Lateral movement patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LateralMovementPattern {
    SequentialHopping,
    AdminToolUsage(Vec<String>),
    CredentialReuse,
    PassTheHash,
    PassTheTicket,
}

/// Result from lateral movement detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementResult {
    pub entity_id: String,
    pub unique_hosts: Vec<String>,
    pub access_chain: Vec<HostAccess>,
    pub time_window_minutes: i32,
    pub velocity_hosts_per_hour: f64,
    pub patterns: Vec<LateralMovementPattern>,
    pub risk_score: i32,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Data exfiltration indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExfiltrationIndicator {
    LargeVolume {
        bytes_transferred: i64,
        threshold_mb: f64,
    },
    ExternalDestination(String),
    SensitiveFileTypes(Vec<String>),
    EncryptedTransfer,
    OffHoursTiming,
    CumulativeVolumeExceeded {
        cumulative_mb: f64,
        window_hours: i32,
    },
    NewDestination(String),
}

/// Result from data exfiltration detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExfiltrationResult {
    pub entity_id: String,
    pub destination: String,
    pub destination_type: String,
    pub bytes_transferred: i64,
    pub file_count: Option<i32>,
    pub indicators: Vec<ExfiltrationIndicator>,
    pub cumulative_bytes_in_window: i64,
    pub is_external: bool,
    pub risk_score: i32,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Peer comparison result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerComparison {
    pub peer_group_id: String,
    pub peer_count: i64,
    pub peers_with_access: i64,
    pub peer_percentage: f64,
    pub avg_peer_access: f64,
    pub deviation_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_sensitivity_multipliers() {
        assert_eq!(DataSensitivity::Public.risk_multiplier(), 0.5);
        assert_eq!(DataSensitivity::Internal.risk_multiplier(), 1.0);
        assert_eq!(DataSensitivity::Confidential.risk_multiplier(), 2.0);
        assert_eq!(DataSensitivity::Restricted.risk_multiplier(), 3.0);
        assert_eq!(DataSensitivity::TopSecret.risk_multiplier(), 5.0);
    }

    #[test]
    fn test_config_defaults() {
        let config = AdvancedDetectionConfig::default();
        assert_eq!(config.max_travel_speed_kmh, 900.0);
        assert_eq!(config.lateral_movement_host_threshold, 5);
        assert_eq!(config.exfiltration_threshold_mb, 100.0);
    }
}
