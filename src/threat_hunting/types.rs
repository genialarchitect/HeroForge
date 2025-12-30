use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Hypothesis status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HypothesisStatus {
    Draft,
    Active,
    Validated,
    Invalidated,
}

impl std::fmt::Display for HypothesisStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HypothesisStatus::Draft => write!(f, "draft"),
            HypothesisStatus::Active => write!(f, "active"),
            HypothesisStatus::Validated => write!(f, "validated"),
            HypothesisStatus::Invalidated => write!(f, "invalidated"),
        }
    }
}

impl std::str::FromStr for HypothesisStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "draft" => Ok(HypothesisStatus::Draft),
            "active" => Ok(HypothesisStatus::Active),
            "validated" => Ok(HypothesisStatus::Validated),
            "invalidated" => Ok(HypothesisStatus::Invalidated),
            _ => Err(anyhow::anyhow!("Invalid hypothesis status: {}", s)),
        }
    }
}

/// Hunt hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub expected_outcome: Option<String>,
    pub status: HypothesisStatus,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateHypothesisRequest {
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub expected_outcome: Option<String>,
}

/// Request to update a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHypothesisRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub query: Option<String>,
    pub expected_outcome: Option<String>,
    pub status: Option<HypothesisStatus>,
}

/// Campaign status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CampaignStatus {
    Planning,
    Active,
    Completed,
    Cancelled,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CampaignStatus::Planning => write!(f, "planning"),
            CampaignStatus::Active => write!(f, "active"),
            CampaignStatus::Completed => write!(f, "completed"),
            CampaignStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for CampaignStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "planning" => Ok(CampaignStatus::Planning),
            "active" => Ok(CampaignStatus::Active),
            "completed" => Ok(CampaignStatus::Completed),
            "cancelled" => Ok(CampaignStatus::Cancelled),
            _ => Err(anyhow::anyhow!("Invalid campaign status: {}", s)),
        }
    }
}

/// Hunt campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntCampaign {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub status: CampaignStatus,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a campaign
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub description: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

/// Execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionStatus::Running => write!(f, "running"),
            ExecutionStatus::Completed => write!(f, "completed"),
            ExecutionStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for ExecutionStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "running" => Ok(ExecutionStatus::Running),
            "completed" => Ok(ExecutionStatus::Completed),
            "failed" => Ok(ExecutionStatus::Failed),
            _ => Err(anyhow::anyhow!("Invalid execution status: {}", s)),
        }
    }
}

/// Hunt execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntExecution {
    pub id: String,
    pub hypothesis_id: Option<String>,
    pub campaign_id: Option<String>,
    pub executed_at: DateTime<Utc>,
    pub results: serde_json::Value,
    pub findings_count: i64,
    pub false_positives: i64,
    pub status: ExecutionStatus,
}

/// Hunt query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntQuery {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub query_dsl: String,
    pub category: Option<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// Hunt notebook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntNotebook {
    pub id: String,
    pub name: String,
    pub content: serde_json::Value,
    pub shared_with: Vec<String>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Hunt analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntAnalytics {
    pub total_hunts: i64,
    pub active_hypotheses: i64,
    pub validated_hypotheses: i64,
    pub total_findings: i64,
    pub false_positive_rate: f64,
    pub average_hunt_duration_seconds: f64,
    pub top_hunters: Vec<HunterMetric>,
}

/// Hunter performance metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HunterMetric {
    pub user_id: String,
    pub hunts_executed: i64,
    pub findings_count: i64,
    pub validated_count: i64,
}

/// Query parse request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseQueryRequest {
    pub query: String,
}

/// Query parse response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseQueryResponse {
    pub valid: bool,
    pub ast: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Query execution request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteQueryRequest {
    pub query: String,
    pub time_range: Option<TimeRange>,
    pub limit: Option<i64>,
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Query execution response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteQueryResponse {
    pub results: Vec<serde_json::Value>,
    pub count: i64,
    pub execution_time_ms: i64,
}
