#![allow(dead_code)]
//! Types for Infrastructure-as-Code (IaC) security scanning
//!
//! This module defines data structures for scanning Terraform, CloudFormation,
//! and Azure ARM templates for security misconfigurations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IaC platform/format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IacPlatform {
    Terraform,
    CloudFormation,
    AzureArm,
    Kubernetes,
    Docker,
}

impl std::fmt::Display for IacPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacPlatform::Terraform => write!(f, "terraform"),
            IacPlatform::CloudFormation => write!(f, "cloudformation"),
            IacPlatform::AzureArm => write!(f, "azure_arm"),
            IacPlatform::Kubernetes => write!(f, "kubernetes"),
            IacPlatform::Docker => write!(f, "docker"),
        }
    }
}

impl std::str::FromStr for IacPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terraform" | "tf" | "hcl" => Ok(IacPlatform::Terraform),
            "cloudformation" | "cfn" | "aws" => Ok(IacPlatform::CloudFormation),
            "azure_arm" | "arm" | "azure" => Ok(IacPlatform::AzureArm),
            "kubernetes" | "k8s" => Ok(IacPlatform::Kubernetes),
            "docker" | "dockerfile" => Ok(IacPlatform::Docker),
            _ => Err(format!("Unknown IaC platform: {}", s)),
        }
    }
}

/// Cloud provider targeted by the IaC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IacCloudProvider {
    Aws,
    Azure,
    Gcp,
    Multi,
    None,
}

impl std::fmt::Display for IacCloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacCloudProvider::Aws => write!(f, "aws"),
            IacCloudProvider::Azure => write!(f, "azure"),
            IacCloudProvider::Gcp => write!(f, "gcp"),
            IacCloudProvider::Multi => write!(f, "multi"),
            IacCloudProvider::None => write!(f, "none"),
        }
    }
}

/// Severity levels for IaC findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum IacSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for IacSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacSeverity::Info => write!(f, "info"),
            IacSeverity::Low => write!(f, "low"),
            IacSeverity::Medium => write!(f, "medium"),
            IacSeverity::High => write!(f, "high"),
            IacSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for IacSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Ok(IacSeverity::Info),
            "low" => Ok(IacSeverity::Low),
            "medium" | "moderate" => Ok(IacSeverity::Medium),
            "high" => Ok(IacSeverity::High),
            "critical" => Ok(IacSeverity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Category of IaC security finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IacFindingCategory {
    /// Hardcoded secrets (API keys, passwords, tokens)
    HardcodedSecret,
    /// Overly permissive IAM policies
    IamMisconfiguration,
    /// Public storage (S3, GCS, Azure Blob)
    PublicStorage,
    /// Missing encryption (at rest or in transit)
    MissingEncryption,
    /// Missing logging or monitoring
    MissingLogging,
    /// Insecure network configuration
    NetworkExposure,
    /// Missing required tags
    MissingTags,
    /// Deprecated or insecure resource type
    DeprecatedResource,
    /// Weak cryptography
    WeakCryptography,
    /// Insecure defaults
    InsecureDefault,
    /// Compliance violation
    ComplianceViolation,
    /// Best practice deviation
    BestPractice,
    /// Data protection and backup issues
    DataProtection,
    /// Disaster recovery and availability issues
    DisasterRecovery,
}

impl std::fmt::Display for IacFindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacFindingCategory::HardcodedSecret => write!(f, "hardcoded_secret"),
            IacFindingCategory::IamMisconfiguration => write!(f, "iam_misconfiguration"),
            IacFindingCategory::PublicStorage => write!(f, "public_storage"),
            IacFindingCategory::MissingEncryption => write!(f, "missing_encryption"),
            IacFindingCategory::MissingLogging => write!(f, "missing_logging"),
            IacFindingCategory::NetworkExposure => write!(f, "network_exposure"),
            IacFindingCategory::MissingTags => write!(f, "missing_tags"),
            IacFindingCategory::DeprecatedResource => write!(f, "deprecated_resource"),
            IacFindingCategory::WeakCryptography => write!(f, "weak_cryptography"),
            IacFindingCategory::InsecureDefault => write!(f, "insecure_default"),
            IacFindingCategory::ComplianceViolation => write!(f, "compliance_violation"),
            IacFindingCategory::BestPractice => write!(f, "best_practice"),
            IacFindingCategory::DataProtection => write!(f, "data_protection"),
            IacFindingCategory::DisasterRecovery => write!(f, "disaster_recovery"),
        }
    }
}

/// IaC resource type being analyzed
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IacResourceType {
    // AWS Resources
    AwsS3Bucket,
    AwsIamRole,
    AwsIamPolicy,
    AwsIamUser,
    AwsEc2Instance,
    AwsSecurityGroup,
    AwsRdsInstance,
    AwsLambdaFunction,
    AwsKmsKey,
    AwsEbsVolume,
    AwsElb,
    AwsSns,
    AwsSqs,
    AwsCloudwatch,
    AwsVpc,
    AwsSubnet,
    AwsEks,
    AwsEcs,
    AwsElasticache,
    AwsDynamodb,
    AwsSecretsManager,
    AwsCloudtrail,
    AwsApiGateway,
    AwsElasticsearch,
    AwsEcr,
    AwsCognito,
    AwsGuardDuty,
    AwsRedshift,
    AwsWaf,

    // Azure Resources
    AzureStorageAccount,
    AzureBlobContainer,
    AzureRoleAssignment,
    AzureVirtualMachine,
    AzureNetworkSecurityGroup,
    AzureSqlServer,
    AzureSqlDatabase,
    AzureKeyVault,
    AzureAppService,
    AzureFunctionApp,
    AzureCosmosDb,
    AzureAks,
    AzureContainerRegistry,
    AzureRedis,
    AzureServiceBus,
    AzureEventHub,
    AzureSynapse,
    AzureDataFactory,
    AzureSecurityCenter,
    AzureLogAnalytics,
    AzureContainerInstance,

    // GCP Resources
    GcpStorageBucket,
    GcpIamBinding,
    GcpIamMember,
    GcpComputeInstance,
    GcpFirewallRule,
    GcpCloudSql,
    GcpKmsKey,
    GcpCloudFunction,
    GcpGke,
    GcpBigQuery,
    GcpPubSub,
    GcpSecretManager,
    GcpCloudRun,
    GcpDataproc,
    GcpVpcNetwork,
    GcpSubnetwork,
    GcpServiceAccount,

    // Kubernetes Resources
    K8sDeployment,
    K8sPod,
    K8sService,
    K8sConfigMap,
    K8sSecret,
    K8sNetworkPolicy,
    K8sRoleBinding,
    K8sClusterRole,

    // Docker
    DockerImage,
    DockerContainer,

    // Generic
    Other(String),
}

impl std::fmt::Display for IacResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacResourceType::AwsS3Bucket => write!(f, "aws_s3_bucket"),
            IacResourceType::AwsIamRole => write!(f, "aws_iam_role"),
            IacResourceType::AwsIamPolicy => write!(f, "aws_iam_policy"),
            IacResourceType::AwsIamUser => write!(f, "aws_iam_user"),
            IacResourceType::AwsEc2Instance => write!(f, "aws_ec2_instance"),
            IacResourceType::AwsSecurityGroup => write!(f, "aws_security_group"),
            IacResourceType::AwsRdsInstance => write!(f, "aws_rds_instance"),
            IacResourceType::AwsLambdaFunction => write!(f, "aws_lambda_function"),
            IacResourceType::AwsKmsKey => write!(f, "aws_kms_key"),
            IacResourceType::AwsEbsVolume => write!(f, "aws_ebs_volume"),
            IacResourceType::AwsElb => write!(f, "aws_elb"),
            IacResourceType::AwsSns => write!(f, "aws_sns"),
            IacResourceType::AwsSqs => write!(f, "aws_sqs"),
            IacResourceType::AwsCloudwatch => write!(f, "aws_cloudwatch"),
            IacResourceType::AwsVpc => write!(f, "aws_vpc"),
            IacResourceType::AwsSubnet => write!(f, "aws_subnet"),
            IacResourceType::AwsEks => write!(f, "aws_eks"),
            IacResourceType::AwsEcs => write!(f, "aws_ecs"),
            IacResourceType::AwsElasticache => write!(f, "aws_elasticache"),
            IacResourceType::AwsDynamodb => write!(f, "aws_dynamodb"),
            IacResourceType::AwsSecretsManager => write!(f, "aws_secrets_manager"),
            IacResourceType::AwsCloudtrail => write!(f, "aws_cloudtrail"),
            IacResourceType::AwsApiGateway => write!(f, "aws_api_gateway"),
            IacResourceType::AwsElasticsearch => write!(f, "aws_elasticsearch"),
            IacResourceType::AwsEcr => write!(f, "aws_ecr"),
            IacResourceType::AwsCognito => write!(f, "aws_cognito"),
            IacResourceType::AwsGuardDuty => write!(f, "aws_guardduty"),
            IacResourceType::AwsRedshift => write!(f, "aws_redshift"),
            IacResourceType::AwsWaf => write!(f, "aws_waf"),
            IacResourceType::AzureStorageAccount => write!(f, "azure_storage_account"),
            IacResourceType::AzureBlobContainer => write!(f, "azure_blob_container"),
            IacResourceType::AzureRoleAssignment => write!(f, "azure_role_assignment"),
            IacResourceType::AzureVirtualMachine => write!(f, "azure_virtual_machine"),
            IacResourceType::AzureNetworkSecurityGroup => write!(f, "azure_network_security_group"),
            IacResourceType::AzureSqlServer => write!(f, "azure_sql_server"),
            IacResourceType::AzureSqlDatabase => write!(f, "azure_sql_database"),
            IacResourceType::AzureKeyVault => write!(f, "azure_key_vault"),
            IacResourceType::AzureAppService => write!(f, "azure_app_service"),
            IacResourceType::AzureFunctionApp => write!(f, "azure_function_app"),
            IacResourceType::AzureCosmosDb => write!(f, "azure_cosmos_db"),
            IacResourceType::AzureAks => write!(f, "azure_aks"),
            IacResourceType::AzureContainerRegistry => write!(f, "azure_container_registry"),
            IacResourceType::AzureRedis => write!(f, "azure_redis"),
            IacResourceType::AzureServiceBus => write!(f, "azure_service_bus"),
            IacResourceType::AzureEventHub => write!(f, "azure_event_hub"),
            IacResourceType::AzureSynapse => write!(f, "azure_synapse"),
            IacResourceType::AzureDataFactory => write!(f, "azure_data_factory"),
            IacResourceType::AzureSecurityCenter => write!(f, "azure_security_center"),
            IacResourceType::AzureLogAnalytics => write!(f, "azure_log_analytics"),
            IacResourceType::AzureContainerInstance => write!(f, "azure_container_instance"),
            IacResourceType::GcpStorageBucket => write!(f, "gcp_storage_bucket"),
            IacResourceType::GcpIamBinding => write!(f, "gcp_iam_binding"),
            IacResourceType::GcpIamMember => write!(f, "gcp_iam_member"),
            IacResourceType::GcpComputeInstance => write!(f, "gcp_compute_instance"),
            IacResourceType::GcpFirewallRule => write!(f, "gcp_firewall_rule"),
            IacResourceType::GcpCloudSql => write!(f, "gcp_cloud_sql"),
            IacResourceType::GcpKmsKey => write!(f, "gcp_kms_key"),
            IacResourceType::GcpCloudFunction => write!(f, "gcp_cloud_function"),
            IacResourceType::GcpGke => write!(f, "gcp_gke"),
            IacResourceType::GcpBigQuery => write!(f, "gcp_bigquery"),
            IacResourceType::GcpPubSub => write!(f, "gcp_pubsub"),
            IacResourceType::GcpSecretManager => write!(f, "gcp_secret_manager"),
            IacResourceType::GcpCloudRun => write!(f, "gcp_cloud_run"),
            IacResourceType::GcpDataproc => write!(f, "gcp_dataproc"),
            IacResourceType::GcpVpcNetwork => write!(f, "gcp_vpc_network"),
            IacResourceType::GcpSubnetwork => write!(f, "gcp_subnetwork"),
            IacResourceType::GcpServiceAccount => write!(f, "gcp_service_account"),
            IacResourceType::K8sDeployment => write!(f, "k8s_deployment"),
            IacResourceType::K8sPod => write!(f, "k8s_pod"),
            IacResourceType::K8sService => write!(f, "k8s_service"),
            IacResourceType::K8sConfigMap => write!(f, "k8s_configmap"),
            IacResourceType::K8sSecret => write!(f, "k8s_secret"),
            IacResourceType::K8sNetworkPolicy => write!(f, "k8s_network_policy"),
            IacResourceType::K8sRoleBinding => write!(f, "k8s_role_binding"),
            IacResourceType::K8sClusterRole => write!(f, "k8s_cluster_role"),
            IacResourceType::DockerImage => write!(f, "docker_image"),
            IacResourceType::DockerContainer => write!(f, "docker_container"),
            IacResourceType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// IaC scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IacScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for IacScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacScanStatus::Pending => write!(f, "pending"),
            IacScanStatus::Running => write!(f, "running"),
            IacScanStatus::Completed => write!(f, "completed"),
            IacScanStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for IacScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(IacScanStatus::Pending),
            "running" => Ok(IacScanStatus::Running),
            "completed" => Ok(IacScanStatus::Completed),
            "failed" => Ok(IacScanStatus::Failed),
            _ => Err(format!("Unknown scan status: {}", s)),
        }
    }
}

/// Source of IaC files to scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum IacSource {
    /// Upload files directly
    Upload {
        files: Vec<IacFile>,
    },
    /// Git repository URL
    GitRepo {
        url: String,
        branch: Option<String>,
        path: Option<String>,
    },
    /// Direct content (for single file analysis)
    DirectContent {
        filename: String,
        content: String,
        platform: Option<IacPlatform>,
    },
}

/// An IaC file to scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFile {
    pub id: String,
    pub scan_id: String,
    pub filename: String,
    pub path: String,
    pub content: Option<String>,
    pub platform: IacPlatform,
    pub provider: IacCloudProvider,
    pub size_bytes: i64,
    pub line_count: i32,
    pub resource_count: i32,
    pub finding_count: i32,
    pub created_at: DateTime<Utc>,
}

/// A discovered resource in IaC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacResource {
    pub id: String,
    pub file_id: String,
    pub resource_type: IacResourceType,
    pub resource_name: String,
    pub provider: IacCloudProvider,
    pub line_start: i32,
    pub line_end: i32,
    pub attributes: HashMap<String, serde_json::Value>,
}

/// A security finding in IaC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFinding {
    pub id: String,
    pub scan_id: String,
    pub file_id: String,
    pub rule_id: String,
    pub severity: IacSeverity,
    pub category: IacFindingCategory,
    pub title: String,
    pub description: String,
    pub resource_type: Option<IacResourceType>,
    pub resource_name: Option<String>,
    pub line_start: i32,
    pub line_end: i32,
    pub code_snippet: Option<String>,
    pub remediation: String,
    pub documentation_url: Option<String>,
    pub compliance_mappings: Vec<IacComplianceMapping>,
    pub status: IacFindingStatus,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Status of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IacFindingStatus {
    Open,
    Resolved,
    FalsePositive,
    Accepted,
    Suppressed,
}

impl std::fmt::Display for IacFindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IacFindingStatus::Open => write!(f, "open"),
            IacFindingStatus::Resolved => write!(f, "resolved"),
            IacFindingStatus::FalsePositive => write!(f, "false_positive"),
            IacFindingStatus::Accepted => write!(f, "accepted"),
            IacFindingStatus::Suppressed => write!(f, "suppressed"),
        }
    }
}

/// Compliance framework mapping for findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacComplianceMapping {
    pub framework: String,
    pub control_id: String,
    pub control_title: Option<String>,
}

/// An IaC security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: IacSeverity,
    pub category: IacFindingCategory,
    pub platforms: Vec<IacPlatform>,
    pub providers: Vec<IacCloudProvider>,
    pub resource_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: RulePatternType,
    pub remediation: String,
    pub documentation_url: Option<String>,
    pub compliance_mappings: Vec<IacComplianceMapping>,
    pub is_builtin: bool,
    pub is_enabled: bool,
    pub user_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Type of pattern for rule matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePatternType {
    /// Regex pattern
    Regex,
    /// JSON path query
    JsonPath,
    /// Custom logic (built-in rules)
    Custom,
}

impl std::fmt::Display for RulePatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RulePatternType::Regex => write!(f, "regex"),
            RulePatternType::JsonPath => write!(f, "jsonpath"),
            RulePatternType::Custom => write!(f, "custom"),
        }
    }
}

/// IaC scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub source_type: String,
    pub source_url: Option<String>,
    pub platforms: Vec<IacPlatform>,
    pub providers: Vec<IacCloudProvider>,
    pub status: IacScanStatus,
    pub file_count: i32,
    pub resource_count: i32,
    pub finding_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of an IaC scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacScanSummary {
    pub id: String,
    pub name: String,
    pub status: IacScanStatus,
    pub platforms: Vec<IacPlatform>,
    pub file_count: i32,
    pub finding_count: i32,
    pub findings_by_severity: HashMap<String, i32>,
    pub findings_by_category: HashMap<String, i32>,
    pub resources_by_type: HashMap<String, i32>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Full IaC scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacScanResults {
    pub scan: IacScan,
    pub files: Vec<IacFile>,
    pub findings: Vec<IacFinding>,
    pub summary: IacScanSummary,
}

/// Request to create a new IaC scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIacScanRequest {
    pub name: String,
    pub source: IacSource,
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Request to analyze a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeFileRequest {
    pub filename: String,
    pub content: String,
    pub platform: Option<IacPlatform>,
}

/// Response from single file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeFileResponse {
    pub platform: IacPlatform,
    pub provider: IacCloudProvider,
    pub resources: Vec<IacResource>,
    pub findings: Vec<IacFinding>,
    pub summary: FileSummary,
}

/// Summary of a single file analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSummary {
    pub line_count: i32,
    pub resource_count: i32,
    pub finding_count: i32,
    pub findings_by_severity: HashMap<String, i32>,
}

/// Request to create a custom rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRuleRequest {
    pub name: String,
    pub description: String,
    pub severity: IacSeverity,
    pub category: IacFindingCategory,
    pub platforms: Vec<IacPlatform>,
    pub providers: Vec<IacCloudProvider>,
    pub resource_types: Vec<String>,
    pub pattern: String,
    pub pattern_type: RulePatternType,
    pub remediation: String,
    pub documentation_url: Option<String>,
    pub compliance_mappings: Vec<IacComplianceMapping>,
}

/// Request to update a custom rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<IacSeverity>,
    pub category: Option<IacFindingCategory>,
    pub platforms: Option<Vec<IacPlatform>>,
    pub providers: Option<Vec<IacCloudProvider>>,
    pub resource_types: Option<Vec<String>>,
    pub pattern: Option<String>,
    pub pattern_type: Option<RulePatternType>,
    pub remediation: Option<String>,
    pub documentation_url: Option<String>,
    pub compliance_mappings: Option<Vec<IacComplianceMapping>>,
    pub is_enabled: Option<bool>,
}

/// Progress update for IaC scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacScanProgress {
    pub scan_id: String,
    pub status: IacScanStatus,
    pub phase: String,
    pub progress_percent: f32,
    pub current_file: Option<String>,
    pub files_scanned: i32,
    pub total_files: i32,
    pub findings_discovered: i32,
    pub message: String,
}
