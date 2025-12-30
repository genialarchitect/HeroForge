use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Patch {
    pub id: String,
    pub patch_id: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub cve_ids: Option<String>, // JSON array
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub priority_score: f64,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PatchDeployment {
    pub id: String,
    pub patch_id: String,
    pub strategy: String, // Canary, BlueGreen, Rolling
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub success_rate: Option<f64>,
    pub rollback_triggered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VirtualPatch {
    pub id: String,
    pub cve_id: String,
    pub patch_type: String, // WAF, IPS, NetworkSegmentation
    pub rule_content: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}
