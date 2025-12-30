//! User Security Context
//!
//! Unified user security context aggregating data from all colored teams.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Unified user security context from all teams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecurityContext {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub department: Option<String>,
    pub role: Option<String>,

    // Orange Team Data (Security Awareness)
    pub orange_team: OrangeTeamContext,

    // Green Team Data (SOC/UEBA)
    pub green_team: GreenTeamContext,

    // Yellow Team Data (Secure Development)
    pub yellow_team: Option<YellowTeamContext>,

    // White Team Data (GRC)
    pub white_team: WhiteTeamContext,

    // Aggregated Risk
    pub overall_risk_score: f64,
    pub risk_level: RiskLevel,

    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrangeTeamContext {
    pub training_completion_rate: f64,
    pub phishing_click_rate: f64,
    pub security_awareness_score: f64,
    pub last_training: Option<DateTime<Utc>>,
    pub training_modules_completed: usize,
    pub badges_earned: usize,
    pub gamification_rank: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreenTeamContext {
    pub incident_count: usize,
    pub insider_threat_score: f64,
    pub suspicious_activity_count: usize,
    pub last_incident: Option<DateTime<Utc>>,
    pub anomaly_detections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YellowTeamContext {
    pub secure_coding_score: f64,
    pub code_review_compliance: f64,
    pub vulnerabilities_introduced: usize,
    pub security_champions: bool,
    pub last_code_scan: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhiteTeamContext {
    pub compliance_violations: usize,
    pub policy_violations: usize,
    pub compliance_status: Vec<ComplianceStatus>,
    pub mandatory_training_complete: bool,
    pub risk_acknowledgements: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub framework: String,
    pub status: String,
    pub last_assessed: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            RiskLevel::Critical
        } else if score >= 60.0 {
            RiskLevel::High
        } else if score >= 40.0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

impl Default for OrangeTeamContext {
    fn default() -> Self {
        Self {
            training_completion_rate: 0.0,
            phishing_click_rate: 0.0,
            security_awareness_score: 0.0,
            last_training: None,
            training_modules_completed: 0,
            badges_earned: 0,
            gamification_rank: None,
        }
    }
}

impl Default for GreenTeamContext {
    fn default() -> Self {
        Self {
            incident_count: 0,
            insider_threat_score: 0.0,
            suspicious_activity_count: 0,
            last_incident: None,
            anomaly_detections: 0,
        }
    }
}

impl Default for WhiteTeamContext {
    fn default() -> Self {
        Self {
            compliance_violations: 0,
            policy_violations: 0,
            compliance_status: Vec::new(),
            mandatory_training_complete: false,
            risk_acknowledgements: 0,
        }
    }
}
