//! Threat Intelligence Context
//!
//! Unified threat intelligence context aggregating data from all teams.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Unified threat intelligence context from all teams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceContext {
    pub threat_id: String,
    pub threat_type: ThreatType,
    pub indicators: Vec<IndicatorOfCompromise>,

    // Red Team Contribution (Discovery)
    pub red_team: ThreatRedTeamContext,

    // Blue Team Contribution (Detection)
    pub blue_team: ThreatBlueTeamContext,

    // Purple Team Contribution (Validation)
    pub purple_team: ThreatPurpleTeamContext,

    // Green Team Contribution (Response)
    pub green_team: ThreatGreenTeamContext,

    // Orange Team Contribution (Awareness)
    pub orange_team: Option<ThreatOrangeTeamContext>,

    // External Intelligence
    pub external_intel: ExternalThreatIntel,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatType {
    Malware,
    Phishing,
    Ransomware,
    APT,
    Insider,
    DDoS,
    DataBreach,
    ZeroDay,
    SupplyChain,
    SocialEngineering,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorOfCompromise {
    pub ioc_type: String, // ip, domain, hash, email, url
    pub value: String,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRedTeamContext {
    pub discovered_via_scan: bool,
    pub exploitability: Exploitability,
    pub affected_assets: Vec<String>,
    pub cvss_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exploitability {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBlueTeamContext {
    pub detection_signatures: Vec<DetectionSignature>,
    pub siem_rules: Vec<String>,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignature {
    pub signature_type: String, // sigma, yara, snort, suricata
    pub signature_id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPurpleTeamContext {
    pub validated: bool,
    pub detection_effectiveness: f64,
    pub exercises_conducted: usize,
    pub last_validation: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatGreenTeamContext {
    pub active_incidents: Vec<String>,
    pub response_playbooks: Vec<String>,
    pub containment_procedures: Vec<String>,
    pub mean_time_to_contain: Option<u64>, // milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatOrangeTeamContext {
    pub training_modules: Vec<String>,
    pub phishing_simulations: usize,
    pub user_awareness_campaigns: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalThreatIntel {
    pub cve_ids: Vec<String>,
    pub mitre_attack_ids: Vec<String>,
    pub threat_actors: Vec<String>,
    pub campaigns: Vec<String>,
    pub references: Vec<String>,
}
