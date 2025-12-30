use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct OrchestrationJob {
    pub id: String,
    pub job_type: String,
    pub target_platform: String, // AWS, Azure, GCP, Edge
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiCloudConfig {
    pub aws_config: Option<AwsConfig>,
    pub azure_config: Option<AzureConfig>,
    pub gcp_config: Option<GcpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub lambda_functions: Vec<String>,
    pub step_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub logic_apps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpConfig {
    pub cloud_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct EdgeNode {
    pub id: String,
    pub name: String,
    pub location: String,
    pub node_type: String, // IoT, Branch, RemoteWorker
    pub status: String,
    pub last_seen: DateTime<Utc>,
}
