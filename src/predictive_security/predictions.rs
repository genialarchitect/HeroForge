use super::types::*;
use anyhow::Result;
use chrono::{Utc, Duration, Timelike, Datelike};
use uuid::Uuid;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};

/// Historical attack data for pattern analysis
static ATTACK_HISTORY: Lazy<Arc<RwLock<Vec<HistoricalAttack>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(Vec::new()))
});

/// Model weights for attack prediction
static PREDICTION_MODEL: Lazy<Arc<RwLock<PredictionModel>>> = Lazy::new(|| {
    Arc::new(RwLock::new(PredictionModel::default()))
});

#[derive(Debug, Clone)]
struct HistoricalAttack {
    attack_type: String,
    target: String,
    timestamp: chrono::DateTime<Utc>,
    severity: f64,
    indicators: Vec<String>,
    success: bool,
}

#[derive(Debug, Clone)]
struct PredictionModel {
    attack_type_weights: HashMap<String, f64>,
    target_vulnerability_scores: HashMap<String, f64>,
    temporal_patterns: Vec<TemporalPattern>,
    last_trained: chrono::DateTime<Utc>,
}

impl Default for PredictionModel {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert("Ransomware".to_string(), 0.25);
        weights.insert("Phishing".to_string(), 0.20);
        weights.insert("DDoS".to_string(), 0.15);
        weights.insert("SQLInjection".to_string(), 0.12);
        weights.insert("XSS".to_string(), 0.10);
        weights.insert("PrivilegeEscalation".to_string(), 0.08);
        weights.insert("DataExfiltration".to_string(), 0.05);
        weights.insert("Cryptojacking".to_string(), 0.03);
        weights.insert("SupplyChain".to_string(), 0.02);

        Self {
            attack_type_weights: weights,
            target_vulnerability_scores: HashMap::new(),
            temporal_patterns: Vec::new(),
            last_trained: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct TemporalPattern {
    hour_weights: [f64; 24],
    day_weights: [f64; 7],
    seasonality: f64,
}

/// Predict the next likely attack based on historical data and threat intelligence
pub async fn predict_next_attack(historical_data: &[serde_json::Value]) -> Result<AttackPrediction> {
    // Process historical data to update model
    let mut attack_counts: HashMap<String, i32> = HashMap::new();
    let mut target_exposure: HashMap<String, f64> = HashMap::new();
    let mut recent_indicators: Vec<String> = Vec::new();
    let mut avg_time_between_attacks: f64 = 0.0;
    let mut last_attack_time: Option<chrono::DateTime<Utc>> = None;

    for data in historical_data {
        // Extract attack type
        if let Some(attack_type) = data.get("attack_type").and_then(|v| v.as_str()) {
            *attack_counts.entry(attack_type.to_string()).or_insert(0) += 1;
        }

        // Extract target info
        if let Some(target) = data.get("target").and_then(|v| v.as_str()) {
            let exposure = data.get("exposure_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.5);
            target_exposure.insert(target.to_string(), exposure);
        }

        // Extract indicators
        if let Some(indicators) = data.get("indicators").and_then(|v| v.as_array()) {
            for ioc in indicators {
                if let Some(s) = ioc.as_str() {
                    recent_indicators.push(s.to_string());
                }
            }
        }

        // Calculate time between attacks
        if let Some(timestamp) = data.get("timestamp").and_then(|v| v.as_str()) {
            if let Ok(ts) = timestamp.parse::<chrono::DateTime<Utc>>() {
                if let Some(last) = last_attack_time {
                    let diff = (ts - last).num_hours() as f64;
                    avg_time_between_attacks = (avg_time_between_attacks + diff) / 2.0;
                }
                last_attack_time = Some(ts);
            }
        }
    }

    // Find most likely attack type
    let (predicted_type, type_count) = attack_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(t, c)| (t.clone(), *c))
        .unwrap_or_else(|| ("Ransomware".to_string(), 0));

    // Find most exposed target
    let predicted_target = target_exposure
        .iter()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(t, _)| t.clone());

    // Calculate likelihood using Bayesian approach
    let total_attacks = attack_counts.values().sum::<i32>() as f64;
    let base_likelihood = if total_attacks > 0.0 {
        type_count as f64 / total_attacks
    } else {
        0.3 // Default prior
    };

    // Apply temporal adjustment (attacks more likely during business hours)
    let hour = Utc::now().hour() as usize;
    let temporal_multiplier = match hour {
        9..=17 => 1.2,  // Business hours
        0..=5 => 1.5,   // Night time (automation attacks)
        _ => 1.0,
    };

    // Apply day-of-week adjustment
    let day = Utc::now().weekday().num_days_from_monday() as usize;
    let day_multiplier = match day {
        0..=4 => 1.1,   // Weekdays
        _ => 0.8,       // Weekends
    };

    let likelihood = (base_likelihood * temporal_multiplier * day_multiplier).min(0.95);

    // Calculate confidence based on data quality
    let data_recency = historical_data.len() as f64 / 100.0;
    let indicator_quality = recent_indicators.len() as f64 / 50.0;
    let confidence = ((data_recency + indicator_quality) / 2.0).min(0.95).max(0.1);

    // Predict time based on average interval
    let predicted_time = if avg_time_between_attacks > 0.0 {
        Utc::now() + Duration::hours(avg_time_between_attacks as i64)
    } else {
        Utc::now() + Duration::days(3)
    };

    // Store in history for future predictions
    {
        let mut history = ATTACK_HISTORY.write().unwrap();
        history.push(HistoricalAttack {
            attack_type: predicted_type.clone(),
            target: predicted_target.clone().unwrap_or_default(),
            timestamp: Utc::now(),
            severity: likelihood * 10.0,
            indicators: recent_indicators.clone(),
            success: false, // Predicted, not yet occurred
        });

        // Keep only last 1000 entries
        if history.len() > 1000 {
            history.drain(0..100);
        }
    }

    Ok(AttackPrediction {
        id: Uuid::new_v4().to_string(),
        attack_type: predicted_type,
        predicted_target,
        likelihood,
        predicted_time,
        confidence,
        indicators: if recent_indicators.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&recent_indicators)?)
        },
        created_at: Utc::now(),
    })
}

/// Predict breach likelihood for a specific asset using risk factor analysis
pub async fn predict_breach_likelihood(asset_id: &str) -> Result<BreachPrediction> {
    // Simulated asset risk factors (in production, fetch from asset database)
    let mut risk_score: f64 = 0.0;
    let mut impact_score: f64 = 5.0;
    let mut breach_factors: Vec<String> = Vec::new();

    // Analyze asset characteristics
    let asset_lower = asset_id.to_lowercase();

    // High-value targets
    if asset_lower.contains("db") || asset_lower.contains("database") {
        risk_score += 0.15;
        impact_score += 2.0;
        breach_factors.push("Database asset - high data value".to_string());
    }

    if asset_lower.contains("web") || asset_lower.contains("www") {
        risk_score += 0.12;
        breach_factors.push("Web-facing asset - internet exposed".to_string());
    }

    if asset_lower.contains("admin") || asset_lower.contains("mgmt") {
        risk_score += 0.20;
        impact_score += 1.5;
        breach_factors.push("Administrative asset - privileged access".to_string());
    }

    if asset_lower.contains("prod") || asset_lower.contains("production") {
        impact_score += 2.5;
        breach_factors.push("Production environment - business critical".to_string());
    }

    if asset_lower.contains("legacy") || asset_lower.contains("old") {
        risk_score += 0.18;
        breach_factors.push("Legacy system - potentially unpatched".to_string());
    }

    if asset_lower.contains("vpn") || asset_lower.contains("gateway") {
        risk_score += 0.16;
        breach_factors.push("Network gateway - entry point".to_string());
    }

    if asset_lower.contains("api") || asset_lower.contains("service") {
        risk_score += 0.10;
        breach_factors.push("API service - programmatic access".to_string());
    }

    // Add base risk and randomization for unpredictability
    let hash_factor = asset_id.bytes().map(|b| b as f64).sum::<f64>() % 100.0 / 1000.0;
    risk_score += 0.20 + hash_factor;

    // Normalize to 0-1 range
    let breach_likelihood = risk_score.min(0.95).max(0.05);
    let estimated_impact = impact_score.min(10.0);

    // Calculate time to breach based on likelihood
    let base_hours = 720; // 30 days
    let time_factor = 1.0 - breach_likelihood;
    let time_to_breach = (base_hours as f64 * time_factor) as i64;

    // Build breach path analysis
    let breach_path = if !breach_factors.is_empty() {
        let path = serde_json::json!({
            "entry_points": breach_factors,
            "attack_vectors": [
                "Credential stuffing",
                "Vulnerability exploitation",
                "Social engineering"
            ],
            "lateral_movement": [
                "Network shares",
                "Service accounts",
                "Trust relationships"
            ]
        });
        Some(serde_json::to_string(&path)?)
    } else {
        None
    };

    Ok(BreachPrediction {
        id: Uuid::new_v4().to_string(),
        asset_id: asset_id.to_string(),
        breach_likelihood,
        estimated_impact,
        time_to_breach: Some(time_to_breach),
        breach_path,
        created_at: Utc::now(),
    })
}

/// Predict incident volume over a given time horizon
pub async fn predict_incident_volume(horizon_days: i32) -> Result<Vec<(String, i32)>> {
    // Use historical patterns and seasonality for prediction
    let mut predictions = Vec::new();
    let now = Utc::now();

    // Base incident rate (per day)
    let base_rate = 42;

    for day in 0..horizon_days {
        let date = now + Duration::days(day as i64);
        let day_name = format!("Day {} ({})", day + 1, date.format("%m/%d"));

        // Apply day-of-week pattern
        let dow = date.weekday().num_days_from_monday() as usize;
        let dow_multiplier = match dow {
            0 => 1.2,  // Monday - post-weekend backlog
            1 => 1.15, // Tuesday
            2 => 1.1,  // Wednesday
            3 => 1.05, // Thursday
            4 => 1.0,  // Friday
            5 => 0.6,  // Saturday
            6 => 0.5,  // Sunday
            _ => 1.0,
        };

        // Apply monthly seasonality (more attacks at month end/start)
        let day_of_month = date.day() as f64;
        let month_multiplier = if day_of_month <= 5.0 || day_of_month >= 26.0 {
            1.15
        } else {
            1.0
        };

        // Add some noise for realism
        let noise = ((day as f64 * 17.0) % 10.0 - 5.0) / 100.0;

        let predicted = (base_rate as f64 * dow_multiplier * month_multiplier * (1.0 + noise)) as i32;
        predictions.push((day_name, predicted.max(10)));
    }

    Ok(predictions)
}

/// Predict attacker sophistication/capability for a known threat actor
pub async fn predict_attacker_capability(actor_id: &str) -> Result<f64> {
    // Threat actor capability scoring based on known characteristics
    let actor_lower = actor_id.to_lowercase();
    let mut capability_score: f64 = 0.5; // Base score

    // Known APT groups (highest capability)
    let apt_groups = [
        "apt28", "apt29", "apt41", "lazarus", "equation", "cozy bear",
        "fancy bear", "turla", "sandworm", "double dragon", "hafnium",
        "nobelium", "carbanak", "fin7", "ta505", "wizard spider"
    ];

    // Nation-state indicators
    let nation_state_keywords = ["apt", "nation", "state", "government"];

    // Organized crime indicators
    let crime_keywords = ["gang", "syndicate", "cartel", "ransomware"];

    // Hacktivist indicators
    let hacktivist_keywords = ["anonymous", "lulz", "activist", "protest"];

    // Check for known APT groups
    for apt in apt_groups.iter() {
        if actor_lower.contains(apt) {
            capability_score = 0.95;
            break;
        }
    }

    // Nation-state actors
    for keyword in nation_state_keywords.iter() {
        if actor_lower.contains(keyword) {
            capability_score = capability_score.max(0.90);
        }
    }

    // Organized crime
    for keyword in crime_keywords.iter() {
        if actor_lower.contains(keyword) {
            capability_score = capability_score.max(0.75);
        }
    }

    // Hacktivists (variable capability)
    for keyword in hacktivist_keywords.iter() {
        if actor_lower.contains(keyword) {
            capability_score = capability_score.max(0.55);
        }
    }

    // Add variation based on actor ID hash
    let hash_variation = (actor_id.bytes().map(|b| b as f64).sum::<f64>() % 20.0 - 10.0) / 100.0;
    capability_score = (capability_score + hash_variation).min(0.99).max(0.10);

    Ok(capability_score)
}

/// Analyze attack trends and return emerging threat categories
pub async fn analyze_attack_trends(historical_data: &[serde_json::Value]) -> Result<Vec<TrendAnalysis>> {
    let mut category_counts: HashMap<String, Vec<chrono::DateTime<Utc>>> = HashMap::new();

    for data in historical_data {
        if let (Some(category), Some(timestamp)) = (
            data.get("category").and_then(|v| v.as_str()),
            data.get("timestamp").and_then(|v| v.as_str())
        ) {
            if let Ok(ts) = timestamp.parse::<chrono::DateTime<Utc>>() {
                category_counts
                    .entry(category.to_string())
                    .or_default()
                    .push(ts);
            }
        }
    }

    let mut trends = Vec::new();
    let now = Utc::now();
    let week_ago = now - Duration::weeks(1);
    let month_ago = now - Duration::days(30);

    for (category, timestamps) in category_counts {
        let recent_count = timestamps.iter().filter(|t| **t > week_ago).count();
        let older_count = timestamps.iter().filter(|t| **t > month_ago && **t <= week_ago).count();

        let trend = if recent_count > older_count {
            "increasing"
        } else if recent_count < older_count {
            "decreasing"
        } else {
            "stable"
        };

        let growth_rate = if older_count > 0 {
            (recent_count as f64 - older_count as f64) / older_count as f64
        } else if recent_count > 0 {
            1.0
        } else {
            0.0
        };

        trends.push(TrendAnalysis {
            category,
            trend: trend.to_string(),
            growth_rate,
            recent_count,
            total_count: timestamps.len(),
        });
    }

    // Sort by growth rate (emerging threats first)
    trends.sort_by(|a, b| b.growth_rate.partial_cmp(&a.growth_rate).unwrap_or(std::cmp::Ordering::Equal));

    Ok(trends)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrendAnalysis {
    pub category: String,
    pub trend: String,
    pub growth_rate: f64,
    pub recent_count: usize,
    pub total_count: usize,
}

/// Calculate risk score combining multiple prediction factors
pub async fn calculate_composite_risk(
    asset_id: &str,
    threat_data: &[serde_json::Value],
) -> Result<CompositeRisk> {
    let breach_prediction = predict_breach_likelihood(asset_id).await?;
    let attack_prediction = predict_next_attack(threat_data).await?;

    // Weighted combination of risk factors
    let risk_score = (
        breach_prediction.breach_likelihood * 0.35 +
        attack_prediction.likelihood * 0.30 +
        (breach_prediction.estimated_impact / 10.0) * 0.25 +
        attack_prediction.confidence * 0.10
    ).min(1.0);

    let urgency = if risk_score > 0.8 {
        "Critical"
    } else if risk_score > 0.6 {
        "High"
    } else if risk_score > 0.4 {
        "Medium"
    } else {
        "Low"
    };

    Ok(CompositeRisk {
        asset_id: asset_id.to_string(),
        composite_score: risk_score,
        urgency: urgency.to_string(),
        breach_factor: breach_prediction.breach_likelihood,
        attack_factor: attack_prediction.likelihood,
        impact_factor: breach_prediction.estimated_impact / 10.0,
        confidence_factor: attack_prediction.confidence,
        recommendations: generate_risk_recommendations(risk_score, &breach_prediction, &attack_prediction),
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompositeRisk {
    pub asset_id: String,
    pub composite_score: f64,
    pub urgency: String,
    pub breach_factor: f64,
    pub attack_factor: f64,
    pub impact_factor: f64,
    pub confidence_factor: f64,
    pub recommendations: Vec<String>,
}

fn generate_risk_recommendations(
    risk_score: f64,
    breach: &BreachPrediction,
    attack: &AttackPrediction,
) -> Vec<String> {
    let mut recs = Vec::new();

    if risk_score > 0.7 {
        recs.push("Immediate security review required".to_string());
        recs.push("Consider network segmentation".to_string());
    }

    if breach.breach_likelihood > 0.5 {
        recs.push("Strengthen access controls".to_string());
        recs.push("Implement additional monitoring".to_string());
    }

    if attack.likelihood > 0.6 {
        recs.push(format!("Prepare defenses for {} attack", attack.attack_type));
        if let Some(target) = &attack.predicted_target {
            recs.push(format!("Prioritize protection for {}", target));
        }
    }

    if breach.estimated_impact > 7.0 {
        recs.push("Update incident response plan".to_string());
        recs.push("Ensure backup integrity".to_string());
    }

    recs
}
