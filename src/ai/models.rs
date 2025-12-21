#![allow(dead_code)]
//! AI Prioritization Data Models
//!
//! Contains all data structures used by the AI prioritization system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Risk category based on effective risk score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RiskCategory {
    Critical,
    High,
    Medium,
    Low,
}

impl RiskCategory {
    /// Determine risk category from score (0-100)
    pub fn from_score(score: f64) -> Self {
        match score as u32 {
            80..=100 => RiskCategory::Critical,
            60..=79 => RiskCategory::High,
            40..=59 => RiskCategory::Medium,
            _ => RiskCategory::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskCategory::Critical => "critical",
            RiskCategory::High => "high",
            RiskCategory::Medium => "medium",
            RiskCategory::Low => "low",
        }
    }
}

impl std::fmt::Display for RiskCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Asset criticality level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AssetCriticality {
    Critical,
    High,
    Medium,
    Low,
}

impl AssetCriticality {
    pub fn score(&self) -> f64 {
        match self {
            AssetCriticality::Critical => 100.0,
            AssetCriticality::High => 75.0,
            AssetCriticality::Medium => 50.0,
            AssetCriticality::Low => 25.0,
        }
    }
}

impl std::fmt::Display for AssetCriticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetCriticality::Critical => write!(f, "critical"),
            AssetCriticality::High => write!(f, "high"),
            AssetCriticality::Medium => write!(f, "medium"),
            AssetCriticality::Low => write!(f, "low"),
        }
    }
}

/// Network exposure level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkExposure {
    InternetFacing,
    Dmz,
    Internal,
    Isolated,
}

impl NetworkExposure {
    pub fn score(&self) -> f64 {
        match self {
            NetworkExposure::InternetFacing => 100.0,
            NetworkExposure::Dmz => 75.0,
            NetworkExposure::Internal => 50.0,
            NetworkExposure::Isolated => 25.0,
        }
    }
}

impl std::fmt::Display for NetworkExposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkExposure::InternetFacing => write!(f, "internet_facing"),
            NetworkExposure::Dmz => write!(f, "dmz"),
            NetworkExposure::Internal => write!(f, "internal"),
            NetworkExposure::Isolated => write!(f, "isolated"),
        }
    }
}

/// Exploit maturity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExploitMaturity {
    /// Active exploitation in the wild
    ActiveExploitation,
    /// Working exploit publicly available
    Functional,
    /// Proof of concept available
    ProofOfConcept,
    /// Theoretical exploit, no public code
    Unproven,
}

impl ExploitMaturity {
    pub fn score(&self) -> f64 {
        match self {
            ExploitMaturity::ActiveExploitation => 100.0,
            ExploitMaturity::Functional => 85.0,
            ExploitMaturity::ProofOfConcept => 60.0,
            ExploitMaturity::Unproven => 30.0,
        }
    }
}

/// Effort level for remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl std::fmt::Display for EffortLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffortLevel::Low => write!(f, "low"),
            EffortLevel::Medium => write!(f, "medium"),
            EffortLevel::High => write!(f, "high"),
            EffortLevel::VeryHigh => write!(f, "very_high"),
        }
    }
}

/// Impact level for remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ImpactLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImpactLevel::Low => write!(f, "low"),
            ImpactLevel::Medium => write!(f, "medium"),
            ImpactLevel::High => write!(f, "high"),
            ImpactLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Configuration for AI model weights
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIModelConfig {
    /// Unique identifier
    pub id: String,
    /// Human-readable name for this configuration
    pub name: String,
    /// Configuration description
    pub description: Option<String>,
    /// Weight factors for scoring
    pub weights: ScoringWeights,
    /// Whether this is the active configuration
    pub is_active: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp
    pub updated_at: DateTime<Utc>,
}

impl Default for AIModelConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Default".to_string(),
            description: Some("Default AI prioritization weights".to_string()),
            weights: ScoringWeights::default(),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Weight factors for vulnerability scoring
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScoringWeights {
    /// Weight for CVSS score (base + temporal + environmental)
    pub cvss_weight: f64,
    /// Weight for exploit availability
    pub exploit_weight: f64,
    /// Weight for asset criticality
    pub asset_criticality_weight: f64,
    /// Weight for network exposure
    pub network_exposure_weight: f64,
    /// Weight for attack path analysis
    pub attack_path_weight: f64,
    /// Weight for compliance impact
    pub compliance_weight: f64,
    /// Weight for business context
    pub business_context_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            cvss_weight: 0.25,
            exploit_weight: 0.20,
            asset_criticality_weight: 0.15,
            network_exposure_weight: 0.15,
            attack_path_weight: 0.10,
            compliance_weight: 0.08,
            business_context_weight: 0.07,
        }
    }
}

/// Individual factor score contribution
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FactorScore {
    /// Name of the factor
    pub factor_name: String,
    /// Raw value before normalization
    pub raw_value: f64,
    /// Normalized value (0-100)
    pub normalized_value: f64,
    /// Weight applied to this factor
    pub weight: f64,
    /// Contribution to final score
    pub contribution: f64,
}

/// Remediation effort estimate
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RemediationEffort {
    /// Estimated hours to remediate
    pub estimated_hours: u32,
    /// Effort level category
    pub effort_level: EffortLevel,
    /// Impact level if exploited
    pub impact_level: ImpactLevel,
    /// Whether remediation requires system downtime
    pub requires_downtime: bool,
    /// Whether remediation requires testing
    pub requires_testing: bool,
}

/// AI-calculated vulnerability score
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIVulnerabilityScore {
    /// Vulnerability tracking ID
    pub vulnerability_id: String,
    /// Effective risk score (0-100)
    pub effective_risk_score: f64,
    /// Risk category
    pub risk_category: RiskCategory,
    /// Individual factor scores
    pub factor_scores: Vec<FactorScore>,
    /// Remediation priority (1 = highest priority)
    pub remediation_priority: u32,
    /// Effort estimate
    pub estimated_effort: RemediationEffort,
    /// Confidence in the score (0-100)
    pub confidence: f64,
    /// When this score was calculated
    pub calculated_at: DateTime<Utc>,
}

/// Summary of prioritization results
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrioritizationSummary {
    /// Total vulnerabilities analyzed
    pub total_vulnerabilities: usize,
    /// Count by risk category
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    /// Average effective risk score
    pub average_risk_score: f64,
    /// Highest risk score
    pub highest_risk_score: f64,
}

/// Complete prioritization result for a scan
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIPrioritizationResult {
    /// Scan ID
    pub scan_id: String,
    /// Individual vulnerability scores, sorted by priority
    pub scores: Vec<AIVulnerabilityScore>,
    /// Summary statistics
    pub summary: PrioritizationSummary,
    /// When calculation was performed
    pub calculated_at: DateTime<Utc>,
}

/// Feedback for improving AI scoring
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AIFeedback {
    /// Vulnerability ID
    pub vulnerability_id: String,
    /// User who provided feedback
    pub user_id: String,
    /// Was the priority appropriate?
    pub priority_appropriate: bool,
    /// Suggested adjustment (-2 to +2)
    pub priority_adjustment: i8,
    /// Was the effort estimate accurate?
    pub effort_accurate: bool,
    /// Actual effort in hours (if known)
    pub actual_effort_hours: Option<u32>,
    /// Additional notes
    pub notes: Option<String>,
    /// When feedback was provided
    pub created_at: DateTime<Utc>,
}

/// Request to calculate AI prioritization
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrioritizeRequest {
    /// Force recalculation even if scores exist
    #[serde(default)]
    pub force_recalculate: bool,
}

/// Request to update AI model configuration
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateConfigRequest {
    /// Optional new name
    pub name: Option<String>,
    /// Optional new description
    pub description: Option<String>,
    /// Weight updates
    pub weights: Option<ScoringWeights>,
}

/// Request to submit feedback
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SubmitFeedbackRequest {
    /// Vulnerability ID
    pub vulnerability_id: String,
    /// Was the priority appropriate?
    pub priority_appropriate: bool,
    /// Suggested adjustment (-2 to +2)
    #[serde(default)]
    pub priority_adjustment: i8,
    /// Was the effort estimate accurate?
    #[serde(default)]
    pub effort_accurate: bool,
    /// Actual effort in hours
    pub actual_effort_hours: Option<u32>,
    /// Additional notes
    pub notes: Option<String>,
}

/// Database model for AI scores
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AIScoreRecord {
    pub id: String,
    pub scan_id: String,
    pub vulnerability_id: String,
    pub effective_risk_score: f64,
    pub risk_category: String,
    pub factor_scores: String, // JSON
    pub remediation_priority: i32,
    pub estimated_effort: String, // JSON
    pub confidence: f64,
    pub calculated_at: DateTime<Utc>,
}

/// Database model for AI feedback
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AIFeedbackRecord {
    pub id: String,
    pub vulnerability_id: String,
    pub user_id: String,
    pub priority_appropriate: bool,
    pub priority_adjustment: i32,
    pub effort_accurate: bool,
    pub actual_effort_hours: Option<i32>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database model for AI model configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AIModelConfigRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub weights: String, // JSON
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<AIModelConfigRecord> for AIModelConfig {
    fn from(record: AIModelConfigRecord) -> Self {
        let weights: ScoringWeights =
            serde_json::from_str(&record.weights).unwrap_or_default();
        Self {
            id: record.id,
            name: record.name,
            description: record.description,
            weights,
            is_active: record.is_active,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}
