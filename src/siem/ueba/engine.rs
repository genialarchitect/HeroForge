//! UEBA Engine - Core behavioral analytics engine.
//!
//! This module provides the main UEBA engine that:
//! - Processes activities and detects anomalies
//! - Calculates and updates risk scores
//! - Manages entity baselines
//! - Detects impossible travel and other behavioral anomalies

use anyhow::Result;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::types::*;

/// UEBA Engine configuration
#[derive(Debug, Clone)]
pub struct UebaEngineConfig {
    /// Standard deviation threshold for anomaly detection
    pub baseline_deviation_threshold: f64,
    /// Minimum sample count before baseline is considered stable
    pub min_baseline_samples: i32,
    /// Hours to look back for activity analysis
    pub activity_lookback_hours: i32,
    /// Maximum travel speed in km/h for impossible travel detection
    pub max_travel_speed_kmh: f64,
    /// Failed login threshold for anomaly
    pub failed_login_threshold: i32,
    /// Failed login time window in minutes
    pub failed_login_window_minutes: i32,
    /// Risk score decay factor per day
    pub risk_decay_factor: f64,
    /// Enable impossible travel detection
    pub enable_impossible_travel: bool,
    /// Enable off-hours detection
    pub enable_off_hours_detection: bool,
    /// Working hours start (0-23)
    pub working_hours_start: u32,
    /// Working hours end (0-23)
    pub working_hours_end: u32,
}

impl Default for UebaEngineConfig {
    fn default() -> Self {
        Self {
            baseline_deviation_threshold: 3.0,
            min_baseline_samples: 30,
            activity_lookback_hours: 24,
            max_travel_speed_kmh: 900.0,
            failed_login_threshold: 5,
            failed_login_window_minutes: 15,
            risk_decay_factor: 0.95,
            enable_impossible_travel: true,
            enable_off_hours_detection: true,
            working_hours_start: 8,
            working_hours_end: 18,
        }
    }
}

/// UEBA Engine for behavioral analytics
pub struct UebaEngine {
    pool: SqlitePool,
    config: UebaEngineConfig,
}

impl UebaEngine {
    /// Create a new UEBA engine
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            config: UebaEngineConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(pool: SqlitePool, config: UebaEngineConfig) -> Self {
        Self { pool, config }
    }

    /// Process an activity and check for anomalies
    pub async fn process_activity(
        &self,
        user_id: &str,
        activity: &RecordActivityRequest,
    ) -> Result<ProcessActivityResult> {
        let now = Utc::now();
        let timestamp = activity.timestamp.as_ref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now);

        // Get or create the entity
        let entity = self.get_or_create_entity(user_id, &activity.entity_id).await?;

        // Create the activity record
        let activity_id = Uuid::new_v4().to_string();
        let mut is_anomalous = false;
        let mut anomaly_reasons: Vec<String> = Vec::new();
        let mut detected_anomalies: Vec<DetectedAnomaly> = Vec::new();

        // Check for various anomaly types
        if self.config.enable_impossible_travel {
            if let Some(anomaly) = self.check_impossible_travel(&entity, activity, &timestamp).await? {
                is_anomalous = true;
                anomaly_reasons.push("impossible_travel".to_string());
                detected_anomalies.push(anomaly);
            }
        }

        if self.config.enable_off_hours_detection {
            if let Some(anomaly) = self.check_off_hours_activity(&entity, activity, &timestamp).await? {
                is_anomalous = true;
                anomaly_reasons.push("off_hours_activity".to_string());
                detected_anomalies.push(anomaly);
            }
        }

        // Check for failed login spikes
        if activity.activity_type == "failed_login" {
            if let Some(anomaly) = self.check_failed_login_spike(&entity).await? {
                is_anomalous = true;
                anomaly_reasons.push("excessive_failed_logins".to_string());
                detected_anomalies.push(anomaly);
            }
        }

        // Check for baseline deviations
        if let Some(anomaly) = self.check_baseline_deviation(&entity, activity).await? {
            is_anomalous = true;
            anomaly_reasons.push("baseline_deviation".to_string());
            detected_anomalies.push(anomaly);
        }

        // Calculate risk contribution
        let risk_contribution = self.calculate_activity_risk_contribution(activity, is_anomalous);

        // Insert the activity
        let anomaly_reasons_json = if anomaly_reasons.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&anomaly_reasons)?)
        };

        let source_location = if activity.source_country.is_some() || activity.source_city.is_some() {
            Some(serde_json::json!({
                "country": activity.source_country,
                "city": activity.source_city,
                "lat": activity.source_lat,
                "lon": activity.source_lon,
            }).to_string())
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT INTO ueba_activities (
                id, entity_id, activity_type, source_ip, source_location,
                source_country, source_city, source_lat, source_lon,
                destination, destination_type, action, resource, resource_type,
                status, risk_contribution, is_anomalous, anomaly_reasons,
                raw_event, event_source, timestamp, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&activity_id)
        .bind(&entity.id)
        .bind(&activity.activity_type)
        .bind(&activity.source_ip)
        .bind(&source_location)
        .bind(&activity.source_country)
        .bind(&activity.source_city)
        .bind(&activity.source_lat)
        .bind(&activity.source_lon)
        .bind(&activity.destination)
        .bind(&activity.destination_type)
        .bind(&activity.action)
        .bind(&activity.resource)
        .bind(&activity.resource_type)
        .bind(&activity.status)
        .bind(risk_contribution)
        .bind(is_anomalous)
        .bind(&anomaly_reasons_json)
        .bind(activity.raw_event.as_ref().map(|v| v.to_string()))
        .bind(&activity.event_source)
        .bind(timestamp.to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?;

        // Create anomaly records
        for anomaly in &detected_anomalies {
            self.create_anomaly_record(&entity, anomaly, &activity_id).await?;
        }

        // Update entity risk score if there were anomalies
        if is_anomalous {
            self.update_entity_risk_score(&entity.id).await?;
        }

        // Update entity last activity
        sqlx::query(
            "UPDATE ueba_entities SET last_activity_at = ?, updated_at = ? WHERE id = ?"
        )
        .bind(timestamp.to_rfc3339())
        .bind(now.to_rfc3339())
        .bind(&entity.id)
        .execute(&self.pool)
        .await?;

        Ok(ProcessActivityResult {
            activity_id,
            is_anomalous,
            anomaly_reasons,
            detected_anomalies: detected_anomalies.into_iter().map(|a| a.anomaly_type.as_str().to_string()).collect(),
            risk_contribution,
        })
    }

    /// Check for impossible travel anomaly
    async fn check_impossible_travel(
        &self,
        entity: &UebaEntity,
        activity: &RecordActivityRequest,
        timestamp: &DateTime<Utc>,
    ) -> Result<Option<DetectedAnomaly>> {
        // Need lat/lon for this check
        let (current_lat, current_lon) = match (activity.source_lat, activity.source_lon) {
            (Some(lat), Some(lon)) => (lat, lon),
            _ => return Ok(None),
        };

        // Get the previous session with location
        let previous_session: Option<UebaSession> = sqlx::query_as(
            r#"
            SELECT * FROM ueba_sessions
            WHERE entity_id = ?
            AND source_lat IS NOT NULL
            AND source_lon IS NOT NULL
            AND started_at < ?
            ORDER BY started_at DESC
            LIMIT 1
            "#,
        )
        .bind(&entity.id)
        .bind(timestamp.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;

        let previous_session = match previous_session {
            Some(s) => s,
            None => return Ok(None),
        };

        // Get previous location
        let (prev_lat, prev_lon) = match (previous_session.source_lat, previous_session.source_lon) {
            (Some(lat), Some(lon)) => (lat, lon),
            _ => return Ok(None),
        };

        // Calculate time difference
        let prev_time = DateTime::parse_from_rfc3339(&previous_session.started_at)?
            .with_timezone(&Utc);
        let time_diff = *timestamp - prev_time;
        let hours = time_diff.num_minutes() as f64 / 60.0;

        if hours <= 0.0 {
            return Ok(None);
        }

        // Check if travel is impossible
        let current_loc = GeoLocation {
            lat: current_lat,
            lon: current_lon,
            country: activity.source_country.clone(),
            city: activity.source_city.clone(),
        };
        let prev_loc = GeoLocation {
            lat: prev_lat,
            lon: prev_lon,
            country: previous_session.source_country.clone(),
            city: previous_session.source_city.clone(),
        };

        let distance = current_loc.distance_km(&prev_loc);
        let required_speed = distance / hours;

        if required_speed > self.config.max_travel_speed_kmh {
            let evidence = serde_json::json!({
                "previous_location": {
                    "lat": prev_lat,
                    "lon": prev_lon,
                    "country": prev_loc.country,
                    "city": prev_loc.city,
                    "timestamp": previous_session.started_at,
                },
                "current_location": {
                    "lat": current_lat,
                    "lon": current_lon,
                    "country": current_loc.country,
                    "city": current_loc.city,
                    "timestamp": timestamp.to_rfc3339(),
                },
                "distance_km": distance,
                "time_hours": hours,
                "required_speed_kmh": required_speed,
                "max_allowed_speed_kmh": self.config.max_travel_speed_kmh,
            });

            return Ok(Some(DetectedAnomaly {
                anomaly_type: AnomalyType::ImpossibleTravel,
                severity: "high".to_string(),
                title: format!("Impossible travel detected for {}", entity.display_name.as_deref().unwrap_or(&entity.entity_id)),
                description: format!(
                    "Login from {} ({}) {} hours after login from {} ({}). Distance: {:.0} km, required speed: {:.0} km/h",
                    current_loc.city.as_deref().unwrap_or("unknown"),
                    current_loc.country.as_deref().unwrap_or("unknown"),
                    hours,
                    prev_loc.city.as_deref().unwrap_or("unknown"),
                    prev_loc.country.as_deref().unwrap_or("unknown"),
                    distance,
                    required_speed
                ),
                evidence: evidence.to_string(),
                confidence: 0.9,
                risk_impact: 20,
            }));
        }

        Ok(None)
    }

    /// Check for off-hours activity
    async fn check_off_hours_activity(
        &self,
        entity: &UebaEntity,
        _activity: &RecordActivityRequest,
        timestamp: &DateTime<Utc>,
    ) -> Result<Option<DetectedAnomaly>> {
        let hour = timestamp.hour();

        // Check if outside working hours
        let is_off_hours = hour < self.config.working_hours_start || hour >= self.config.working_hours_end;

        if !is_off_hours {
            return Ok(None);
        }

        // Check if this entity typically has off-hours activity
        let baseline: Option<UebaBaseline> = sqlx::query_as(
            r#"
            SELECT * FROM ueba_baselines
            WHERE entity_id = ?
            AND metric_name = 'off_hours_activity_rate'
            AND is_stable = TRUE
            "#,
        )
        .bind(&entity.id)
        .fetch_optional(&self.pool)
        .await?;

        // If entity typically has off-hours activity, this might be normal
        if let Some(baseline) = baseline {
            if let Some(mean) = baseline.mean_value {
                if mean > 0.3 {
                    // More than 30% off-hours activity is normal for this entity
                    return Ok(None);
                }
            }
        }

        let evidence = serde_json::json!({
            "activity_hour": hour,
            "working_hours": {
                "start": self.config.working_hours_start,
                "end": self.config.working_hours_end,
            },
            "timestamp": timestamp.to_rfc3339(),
        });

        Ok(Some(DetectedAnomaly {
            anomaly_type: AnomalyType::OffHoursActivity,
            severity: "low".to_string(),
            title: format!("Off-hours activity for {}", entity.display_name.as_deref().unwrap_or(&entity.entity_id)),
            description: format!("Activity detected at {} (outside working hours {}:00-{}:00)",
                timestamp.format("%H:%M"),
                self.config.working_hours_start,
                self.config.working_hours_end
            ),
            evidence: evidence.to_string(),
            confidence: 0.7,
            risk_impact: 5,
        }))
    }

    /// Check for failed login spike
    async fn check_failed_login_spike(&self, entity: &UebaEntity) -> Result<Option<DetectedAnomaly>> {
        let window_start = Utc::now() - Duration::minutes(self.config.failed_login_window_minutes as i64);

        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_activities
            WHERE entity_id = ?
            AND activity_type = 'failed_login'
            AND timestamp >= ?
            "#,
        )
        .bind(&entity.id)
        .bind(window_start.to_rfc3339())
        .fetch_one(&self.pool)
        .await?;

        if count.0 >= self.config.failed_login_threshold as i64 {
            let evidence = serde_json::json!({
                "failed_login_count": count.0,
                "threshold": self.config.failed_login_threshold,
                "window_minutes": self.config.failed_login_window_minutes,
            });

            return Ok(Some(DetectedAnomaly {
                anomaly_type: AnomalyType::ExcessiveFailedLogins,
                severity: "medium".to_string(),
                title: format!("Excessive failed logins for {}", entity.display_name.as_deref().unwrap_or(&entity.entity_id)),
                description: format!(
                    "{} failed login attempts in the last {} minutes (threshold: {})",
                    count.0,
                    self.config.failed_login_window_minutes,
                    self.config.failed_login_threshold
                ),
                evidence: evidence.to_string(),
                confidence: 0.95,
                risk_impact: 15,
            }));
        }

        Ok(None)
    }

    /// Check for baseline deviation
    async fn check_baseline_deviation(
        &self,
        entity: &UebaEntity,
        activity: &RecordActivityRequest,
    ) -> Result<Option<DetectedAnomaly>> {
        // Get relevant baseline for this activity type
        let baseline: Option<UebaBaseline> = sqlx::query_as(
            r#"
            SELECT * FROM ueba_baselines
            WHERE entity_id = ?
            AND metric_name = ?
            AND is_stable = TRUE
            "#,
        )
        .bind(&entity.id)
        .bind(format!("{}_count", activity.activity_type))
        .fetch_optional(&self.pool)
        .await?;

        let baseline = match baseline {
            Some(b) => b,
            None => return Ok(None), // No baseline yet
        };

        // Get current count for today
        let today_start = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_activities
            WHERE entity_id = ?
            AND activity_type = ?
            AND timestamp >= ?
            "#,
        )
        .bind(&entity.id)
        .bind(&activity.activity_type)
        .bind(today_start.to_string())
        .fetch_one(&self.pool)
        .await?;

        // Check if deviation is significant
        let (mean, std_dev) = match (baseline.mean_value, baseline.std_deviation) {
            (Some(m), Some(s)) if s > 0.0 => (m, s),
            _ => return Ok(None),
        };

        let deviation = (count.0 as f64 - mean).abs() / std_dev;

        if deviation > self.config.baseline_deviation_threshold {
            let evidence = serde_json::json!({
                "activity_type": activity.activity_type,
                "current_count": count.0,
                "baseline_mean": mean,
                "baseline_std_dev": std_dev,
                "deviation": deviation,
                "threshold": self.config.baseline_deviation_threshold,
            });

            return Ok(Some(DetectedAnomaly {
                anomaly_type: AnomalyType::BaselineDeviation,
                severity: if deviation > 5.0 { "high" } else { "medium" }.to_string(),
                title: format!("Unusual {} activity for {}",
                    activity.activity_type,
                    entity.display_name.as_deref().unwrap_or(&entity.entity_id)
                ),
                description: format!(
                    "{} {} activities today vs baseline of {:.1} (σ={:.1}). Deviation: {:.1}σ",
                    count.0,
                    activity.activity_type,
                    mean,
                    std_dev,
                    deviation
                ),
                evidence: evidence.to_string(),
                confidence: 0.8,
                risk_impact: if deviation > 5.0 { 15 } else { 10 },
            }));
        }

        Ok(None)
    }

    /// Get or create an entity
    async fn get_or_create_entity(&self, user_id: &str, entity_id: &str) -> Result<UebaEntity> {
        // Try to get existing entity
        let existing: Option<UebaEntity> = sqlx::query_as(
            "SELECT * FROM ueba_entities WHERE user_id = ? AND entity_id = ?"
        )
        .bind(user_id)
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(entity) = existing {
            return Ok(entity);
        }

        // Create new entity
        let now = Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO ueba_entities (
                id, user_id, entity_type, entity_id, risk_score, risk_level,
                is_active, is_privileged, is_service_account, first_seen_at,
                created_at, updated_at
            ) VALUES (?, ?, 'user', ?, 0, 'low', TRUE, FALSE, FALSE, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(entity_id)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        // Fetch and return the new entity
        sqlx::query_as("SELECT * FROM ueba_entities WHERE id = ?")
            .bind(&id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Create an anomaly record
    async fn create_anomaly_record(
        &self,
        entity: &UebaEntity,
        anomaly: &DetectedAnomaly,
        activity_id: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let mitre_techniques = anomaly.anomaly_type.mitre_techniques();
        let mitre_json = if mitre_techniques.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&mitre_techniques)?)
        };

        let related_activities = serde_json::to_string(&[activity_id])?;

        sqlx::query(
            r#"
            INSERT INTO ueba_anomalies (
                id, entity_id, anomaly_type, severity, title, description,
                evidence, confidence, status, priority, related_activities,
                mitre_techniques, risk_score_impact, detected_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', 'medium', ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&entity.id)
        .bind(anomaly.anomaly_type.as_str())
        .bind(&anomaly.severity)
        .bind(&anomaly.title)
        .bind(&anomaly.description)
        .bind(&anomaly.evidence)
        .bind(anomaly.confidence)
        .bind(&related_activities)
        .bind(&mitre_json)
        .bind(anomaly.risk_impact)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        // Create a risk factor for this anomaly
        self.add_risk_factor(
            &entity.id,
            RiskFactorType::Anomaly,
            Some(anomaly.anomaly_type.as_str()),
            Some(&anomaly.title),
            anomaly.risk_impact,
            Some("anomaly"),
            Some(&id),
        ).await?;

        Ok(id)
    }

    /// Add a risk factor to an entity
    pub async fn add_risk_factor(
        &self,
        entity_id: &str,
        factor_type: RiskFactorType,
        factor_value: Option<&str>,
        description: Option<&str>,
        contribution: i32,
        source: Option<&str>,
        source_id: Option<&str>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let weight = factor_type.default_weight();

        sqlx::query(
            r#"
            INSERT INTO ueba_risk_factors (
                id, entity_id, factor_type, factor_value, description,
                weight, contribution, source, source_id, valid_from,
                is_active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(entity_id)
        .bind(factor_type.as_str())
        .bind(factor_value)
        .bind(description)
        .bind(weight)
        .bind(contribution)
        .bind(source)
        .bind(source_id)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        // Update entity risk score
        self.update_entity_risk_score(entity_id).await?;

        Ok(id)
    }

    /// Update an entity's risk score based on active risk factors
    pub async fn update_entity_risk_score(&self, entity_id: &str) -> Result<i32> {
        // Get all active risk factors
        let factors: Vec<UebaRiskFactor> = sqlx::query_as(
            r#"
            SELECT * FROM ueba_risk_factors
            WHERE entity_id = ?
            AND is_active = TRUE
            AND (valid_until IS NULL OR valid_until > datetime('now'))
            "#,
        )
        .bind(entity_id)
        .fetch_all(&self.pool)
        .await?;

        // Calculate weighted risk score
        let mut total_score: f64 = 0.0;
        for factor in &factors {
            let contribution = factor.contribution.unwrap_or(0) as f64;
            total_score += contribution * factor.weight;
        }

        // Cap at 100
        let risk_score = (total_score as i32).min(100).max(0);
        let risk_level = RiskLevel::from_score(risk_score);
        let now = Utc::now().to_rfc3339();

        // Update entity
        sqlx::query(
            "UPDATE ueba_entities SET risk_score = ?, risk_level = ?, updated_at = ? WHERE id = ?"
        )
        .bind(risk_score)
        .bind(risk_level.as_str())
        .bind(&now)
        .bind(entity_id)
        .execute(&self.pool)
        .await?;

        // Record in history
        sqlx::query(
            r#"
            INSERT INTO ueba_risk_score_history (
                id, entity_id, risk_score, risk_level, change_reason,
                change_source, factors_snapshot, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(entity_id)
        .bind(risk_score)
        .bind(risk_level.as_str())
        .bind("risk_factors_updated")
        .bind("engine")
        .bind(serde_json::to_string(&factors.iter().map(|f| (&f.factor_type, f.contribution)).collect::<Vec<_>>())?)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(risk_score)
    }

    /// Calculate risk contribution for an activity
    fn calculate_activity_risk_contribution(&self, activity: &RecordActivityRequest, is_anomalous: bool) -> i32 {
        let mut risk = 0;

        // Base risk by activity type
        risk += match activity.activity_type.as_str() {
            "failed_login" => 2,
            "privilege_escalation" => 10,
            "admin_action" => 5,
            "config_change" => 3,
            "policy_violation" => 8,
            "data_download" | "data_upload" => 2,
            _ => 0,
        };

        // Additional risk if anomalous
        if is_anomalous {
            risk += 5;
        }

        risk
    }

    /// Get dashboard statistics
    pub async fn get_dashboard_stats(&self, user_id: &str) -> Result<UebaDashboardStats> {
        // Total entities
        let total_entities: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ueba_entities WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // High risk entities
        let high_risk: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ueba_entities WHERE user_id = ? AND risk_level = 'high'"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Critical risk entities
        let critical_risk: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ueba_entities WHERE user_id = ? AND risk_level = 'critical'"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Total anomalies
        let total_anomalies: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_anomalies a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ?
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // New anomalies
        let new_anomalies: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_anomalies a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ? AND a.status = 'new'
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Open anomalies (new + acknowledged + investigating)
        let open_anomalies: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ueba_anomalies a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ? AND a.status IN ('new', 'acknowledged', 'investigating')
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        // Anomalies by type
        let anomalies_by_type: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT a.anomaly_type, COUNT(*) FROM ueba_anomalies a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ?
            GROUP BY a.anomaly_type
            ORDER BY COUNT(*) DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        // Risk distribution
        let risk_dist: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT risk_level, COUNT(*) FROM ueba_entities
            WHERE user_id = ?
            GROUP BY risk_level
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut distribution = RiskDistribution { low: 0, medium: 0, high: 0, critical: 0 };
        for (level, count) in risk_dist {
            match level.as_str() {
                "low" => distribution.low = count,
                "medium" => distribution.medium = count,
                "high" => distribution.high = count,
                "critical" => distribution.critical = count,
                _ => {}
            }
        }

        // Recent anomalies (last 10)
        let recent_anomalies: Vec<UebaAnomaly> = sqlx::query_as(
            r#"
            SELECT a.* FROM ueba_anomalies a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ?
            ORDER BY a.detected_at DESC
            LIMIT 10
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        // Top risk entities
        let top_risk: Vec<(String, String, Option<String>, i32, String, i64)> = sqlx::query_as(
            r#"
            SELECT e.id, e.entity_type, e.display_name, e.risk_score, e.risk_level,
                   (SELECT COUNT(*) FROM ueba_anomalies WHERE entity_id = e.id) as anomaly_count
            FROM ueba_entities e
            WHERE e.user_id = ?
            ORDER BY e.risk_score DESC
            LIMIT 10
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        // Activity trend - daily counts for the last 14 days
        let activity_trend_raw: Vec<(String, i64, i64)> = sqlx::query_as(
            r#"
            SELECT
                date(a.timestamp) as day,
                COUNT(*) as total_activities,
                SUM(CASE WHEN a.is_anomalous = 1 THEN 1 ELSE 0 END) as anomalous_activities
            FROM ueba_activities a
            JOIN ueba_entities e ON a.entity_id = e.id
            WHERE e.user_id = ?
            AND a.timestamp >= date('now', '-14 days')
            GROUP BY date(a.timestamp)
            ORDER BY day DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let activity_trend: Vec<ActivityTrendPoint> = activity_trend_raw
            .into_iter()
            .map(|(timestamp, total_activities, anomalous_activities)| ActivityTrendPoint {
                timestamp,
                total_activities,
                anomalous_activities,
            })
            .collect();

        Ok(UebaDashboardStats {
            total_entities: total_entities.0,
            high_risk_entities: high_risk.0,
            critical_risk_entities: critical_risk.0,
            total_anomalies: total_anomalies.0,
            new_anomalies: new_anomalies.0,
            open_anomalies: open_anomalies.0,
            anomalies_by_type: anomalies_by_type.into_iter()
                .map(|(t, c)| AnomalyTypeCount { anomaly_type: t, count: c })
                .collect(),
            risk_distribution: distribution,
            recent_anomalies,
            top_risk_entities: top_risk.into_iter()
                .map(|(id, et, dn, rs, rl, ac)| EntityRiskSummary {
                    entity_id: id,
                    entity_type: et,
                    display_name: dn,
                    risk_score: rs,
                    risk_level: rl,
                    anomaly_count: ac,
                    last_activity_at: None,
                })
                .collect(),
            activity_trend,
        })
    }
}

/// Result of processing an activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActivityResult {
    pub activity_id: String,
    pub is_anomalous: bool,
    pub anomaly_reasons: Vec<String>,
    pub detected_anomalies: Vec<String>,
    pub risk_contribution: i32,
}

/// Detected anomaly information
#[derive(Debug, Clone)]
pub struct DetectedAnomaly {
    pub anomaly_type: AnomalyType,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub confidence: f64,
    pub risk_impact: i32,
}

