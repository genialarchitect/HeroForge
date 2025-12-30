use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AttackPrediction {
    pub id: String,
    pub attack_type: String,
    pub predicted_target: Option<String>,
    pub likelihood: f64,
    pub predicted_time: DateTime<Utc>,
    pub confidence: f64,
    pub indicators: Option<String>, // JSON
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BreachPrediction {
    pub id: String,
    pub asset_id: String,
    pub breach_likelihood: f64,
    pub estimated_impact: f64,
    pub time_to_breach: Option<i64>, // hours
    pub breach_path: Option<String>, // JSON
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProactiveAction {
    pub id: String,
    pub action_type: String,
    pub target: String,
    pub rationale: String,
    pub status: String,
    pub executed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
