//! Asset Security Context
//!
//! Unified asset security context aggregating data from all colored teams.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Unified asset security context from all teams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSecurityContext {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub owner: Option<String>,

    // Red Team Data (Offensive Security)
    pub red_team: RedTeamContext,

    // Blue Team Data (Detection & Defense)
    pub blue_team: BlueTeamContext,

    // Green Team Data (SOC/Incidents)
    pub green_team: AssetGreenTeamContext,

    // Purple Team Data (Validation)
    pub purple_team: PurpleTeamContext,

    // White Team Data (GRC)
    pub white_team: AssetWhiteTeamContext,

    // Aggregated Risk
    pub overall_risk_score: f64,
    pub risk_level: String,

    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetType {
    Server,
    Workstation,
    Network,
    Cloud,
    Container,
    Database,
    WebApp,
    Mobile,
    IoT,
    OT,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamContext {
    pub vulnerability_count: usize,
    pub critical_vuln_count: usize,
    pub high_vuln_count: usize,
    pub medium_vuln_count: usize,
    pub low_vuln_count: usize,
    pub last_scan: Option<DateTime<Utc>>,
    pub exploitability_score: f64,
    pub attack_surface_score: f64,
    pub open_ports: usize,
    pub exposed_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTeamContext {
    pub detection_coverage: f64,
    pub monitored: bool,
    pub detection_rule_count: usize,
    pub siem_integrated: bool,
    pub edr_installed: bool,
    pub last_detection: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetGreenTeamContext {
    pub incident_count: usize,
    pub alert_count: usize,
    pub last_incident: Option<DateTime<Utc>>,
    pub mean_time_to_detect: Option<u64>, // milliseconds
    pub mean_time_to_respond: Option<u64>, // milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurpleTeamContext {
    pub attack_simulation_count: usize,
    pub detection_gap_count: usize,
    pub last_exercise: Option<DateTime<Utc>>,
    pub detection_effectiveness: f64,
    pub mitre_coverage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetWhiteTeamContext {
    pub compliance_scopes: Vec<String>, // PCI-DSS, HIPAA, etc.
    pub risk_rating: String,
    pub last_risk_assessment: Option<DateTime<Utc>>,
    pub compliance_violations: usize,
}

impl Default for RedTeamContext {
    fn default() -> Self {
        Self {
            vulnerability_count: 0,
            critical_vuln_count: 0,
            high_vuln_count: 0,
            medium_vuln_count: 0,
            low_vuln_count: 0,
            last_scan: None,
            exploitability_score: 0.0,
            attack_surface_score: 0.0,
            open_ports: 0,
            exposed_services: Vec::new(),
        }
    }
}

impl Default for BlueTeamContext {
    fn default() -> Self {
        Self {
            detection_coverage: 0.0,
            monitored: false,
            detection_rule_count: 0,
            siem_integrated: false,
            edr_installed: false,
            last_detection: None,
        }
    }
}

impl Default for AssetGreenTeamContext {
    fn default() -> Self {
        Self {
            incident_count: 0,
            alert_count: 0,
            last_incident: None,
            mean_time_to_detect: None,
            mean_time_to_respond: None,
        }
    }
}

impl Default for PurpleTeamContext {
    fn default() -> Self {
        Self {
            attack_simulation_count: 0,
            detection_gap_count: 0,
            last_exercise: None,
            detection_effectiveness: 0.0,
            mitre_coverage: 0.0,
        }
    }
}

impl Default for AssetWhiteTeamContext {
    fn default() -> Self {
        Self {
            compliance_scopes: Vec::new(),
            risk_rating: "low".to_string(),
            last_risk_assessment: None,
            compliance_violations: 0,
        }
    }
}
