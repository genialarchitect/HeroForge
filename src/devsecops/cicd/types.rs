//! CI/CD Integration Types
//!
//! Data types for CI/CD pipeline integration.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

/// Supported CI/CD platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CiCdPlatformType {
    GithubActions,
    GitlabCi,
    Jenkins,
    AzureDevops,
}

impl std::fmt::Display for CiCdPlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiCdPlatformType::GithubActions => write!(f, "github_actions"),
            CiCdPlatformType::GitlabCi => write!(f, "gitlab_ci"),
            CiCdPlatformType::Jenkins => write!(f, "jenkins"),
            CiCdPlatformType::AzureDevops => write!(f, "azure_devops"),
        }
    }
}

impl std::str::FromStr for CiCdPlatformType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "github_actions" | "github" => Ok(CiCdPlatformType::GithubActions),
            "gitlab_ci" | "gitlab" => Ok(CiCdPlatformType::GitlabCi),
            "jenkins" => Ok(CiCdPlatformType::Jenkins),
            "azure_devops" | "azure" | "azuredevops" => Ok(CiCdPlatformType::AzureDevops),
            _ => Err(format!("Unknown CI/CD platform: {}", s)),
        }
    }
}

/// Policy types for CI/CD integration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    QualityGate,
    BlockMerge,
    Notification,
}

impl std::fmt::Display for PolicyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyType::QualityGate => write!(f, "quality_gate"),
            PolicyType::BlockMerge => write!(f, "block_merge"),
            PolicyType::Notification => write!(f, "notification"),
        }
    }
}

impl std::str::FromStr for PolicyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quality_gate" => Ok(PolicyType::QualityGate),
            "block_merge" => Ok(PolicyType::BlockMerge),
            "notification" => Ok(PolicyType::Notification),
            _ => Err(format!("Unknown policy type: {}", s)),
        }
    }
}

/// Trigger types for CI/CD runs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    Push,
    PullRequest,
    Schedule,
    Manual,
    Tag,
    Webhook,
}

impl std::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriggerType::Push => write!(f, "push"),
            TriggerType::PullRequest => write!(f, "pr"),
            TriggerType::Schedule => write!(f, "schedule"),
            TriggerType::Manual => write!(f, "manual"),
            TriggerType::Tag => write!(f, "tag"),
            TriggerType::Webhook => write!(f, "webhook"),
        }
    }
}

/// Gate status for quality gates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Failed,
    Warning,
    Pending,
}

impl std::fmt::Display for GateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateStatus::Passed => write!(f, "passed"),
            GateStatus::Failed => write!(f, "failed"),
            GateStatus::Warning => write!(f, "warning"),
            GateStatus::Pending => write!(f, "pending"),
        }
    }
}

/// CI/CD Pipeline configuration record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CiCdPipeline {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub platform: String,
    pub repository_url: Option<String>,
    pub webhook_secret: Option<String>,
    pub enabled: bool,
    pub config: Option<String>,
    pub last_run_at: Option<String>,
    pub last_run_status: Option<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub organization_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// CI/CD Pipeline Run record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CiCdPipelineRun {
    pub id: String,
    pub pipeline_id: String,
    pub external_run_id: Option<String>,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
    pub trigger_type: Option<String>,
    pub pr_number: Option<i32>,
    pub status: String,
    pub gate_status: Option<String>,
    pub findings_new: i32,
    pub findings_fixed: i32,
    pub findings_total: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub duration_seconds: Option<i32>,
    pub scan_id: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// CI/CD Policy record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CiCdPolicy {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    pub conditions: String,
    pub actions: String,
    pub severity_threshold: Option<String>,
    pub max_new_findings: Option<i32>,
    pub max_total_findings: Option<i32>,
    pub block_on_critical: bool,
    pub enabled: bool,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
    pub organization_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// CI/CD Workflow Template record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct CiCdWorkflowTemplate {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub description: Option<String>,
    pub template_content: String,
    pub variables: Option<String>,
    pub is_builtin: bool,
    pub category: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Policy conditions for quality gates
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyConditions {
    /// Minimum severity to consider (critical, high, medium, low, info)
    #[serde(default)]
    pub min_severity: Option<String>,
    /// Maximum allowed new findings
    #[serde(default)]
    pub max_new_findings: Option<i32>,
    /// Maximum allowed total findings
    #[serde(default)]
    pub max_total_findings: Option<i32>,
    /// Maximum allowed critical findings
    #[serde(default)]
    pub max_critical: Option<i32>,
    /// Maximum allowed high severity findings
    #[serde(default)]
    pub max_high: Option<i32>,
    /// Required minimum code coverage (if available)
    #[serde(default)]
    pub min_coverage: Option<f32>,
    /// Custom condition expressions
    #[serde(default)]
    pub custom_expressions: Vec<String>,
}

impl Default for PolicyConditions {
    fn default() -> Self {
        Self {
            min_severity: Some("high".to_string()),
            max_new_findings: Some(0),
            max_total_findings: None,
            max_critical: Some(0),
            max_high: Some(0),
            min_coverage: None,
            custom_expressions: Vec::new(),
        }
    }
}

/// Policy actions when conditions are met/not met
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyActions {
    /// Block merge/deploy if conditions fail
    #[serde(default)]
    pub block_on_fail: bool,
    /// Send notification on failure
    #[serde(default)]
    pub notify_on_fail: bool,
    /// Send notification on success
    #[serde(default)]
    pub notify_on_success: bool,
    /// Create JIRA ticket on failure
    #[serde(default)]
    pub create_ticket_on_fail: bool,
    /// Webhook URLs to call on events
    #[serde(default)]
    pub webhook_urls: Vec<String>,
    /// Comment on PR with results
    #[serde(default)]
    pub comment_on_pr: bool,
    /// Update commit status
    #[serde(default)]
    pub update_commit_status: bool,
}

impl Default for PolicyActions {
    fn default() -> Self {
        Self {
            block_on_fail: true,
            notify_on_fail: true,
            notify_on_success: false,
            create_ticket_on_fail: false,
            webhook_urls: Vec::new(),
            comment_on_pr: true,
            update_commit_status: true,
        }
    }
}

/// Quality gate evaluation result
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QualityGateResult {
    pub status: GateStatus,
    pub passed_conditions: Vec<String>,
    pub failed_conditions: Vec<String>,
    pub warning_conditions: Vec<String>,
    pub summary: String,
    pub details: QualityGateDetails,
}

/// Details of quality gate evaluation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QualityGateDetails {
    pub new_findings: i32,
    pub fixed_findings: i32,
    pub total_findings: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub coverage: Option<f32>,
}

/// Request to create a new pipeline
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatePipelineRequest {
    pub name: String,
    pub platform: String,
    pub repository_url: Option<String>,
    pub config: Option<serde_json::Value>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to update a pipeline
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdatePipelineRequest {
    pub name: Option<String>,
    pub repository_url: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to create a new policy
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    pub conditions: PolicyConditions,
    pub actions: PolicyActions,
    pub severity_threshold: Option<String>,
    pub max_new_findings: Option<i32>,
    pub max_total_findings: Option<i32>,
    pub block_on_critical: Option<bool>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to update a policy
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub conditions: Option<PolicyConditions>,
    pub actions: Option<PolicyActions>,
    pub severity_threshold: Option<String>,
    pub max_new_findings: Option<i32>,
    pub max_total_findings: Option<i32>,
    pub block_on_critical: Option<bool>,
    pub enabled: Option<bool>,
}

/// Webhook payload from CI/CD systems
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CiCdWebhookPayload {
    pub repository: Option<String>,
    pub project_path: Option<String>,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub pr_number: Option<i32>,
    pub mr_iid: Option<i32>,
    pub trigger: Option<String>,
    pub pipeline_id: Option<String>,
    pub build_id: Option<String>,
    pub build_number: Option<String>,
    pub job_name: Option<String>,
    pub url: Option<String>,
    pub project_id: Option<String>,
    pub project: Option<String>,
    pub pr_id: Option<String>,
    /// Files content for scanning
    pub files: Option<Vec<CiCdFileContent>>,
}

/// File content for CI/CD scanning
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CiCdFileContent {
    pub path: String,
    pub content: String,
}

/// Generate template request
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GenerateTemplateRequest {
    pub platform: String,
    pub repository_url: Option<String>,
    pub branch: Option<String>,
    pub scan_types: Option<Vec<String>>,
    pub quality_gate_enabled: Option<bool>,
    pub schedule: Option<String>,
    pub custom_variables: Option<serde_json::Value>,
}

/// Generated template response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedTemplate {
    pub platform: String,
    pub content: String,
    pub filename: String,
    pub variables_required: Vec<String>,
    pub setup_instructions: String,
}
