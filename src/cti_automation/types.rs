use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEnrichment {
    pub ioc: String,
    pub ioc_type: String,
    pub passive_dns: Option<Vec<String>>,
    pub whois_data: Option<serde_json::Value>,
    pub reputation_score: Option<f64>,
    pub sandbox_results: Option<Vec<SandboxResult>>,
    pub ssl_cert_info: Option<serde_json::Value>,
    pub geolocation: Option<Geolocation>,
    pub asn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxResult {
    pub sandbox_name: String,
    pub verdict: String,
    pub score: f64,
    pub behaviors: Vec<String>,
    pub network_activity: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Geolocation {
    pub country: String,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomatedResponse {
    pub response_id: String,
    pub ioc: String,
    pub action: String,
    pub status: String,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
}
