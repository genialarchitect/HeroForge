#![allow(dead_code)]
//! Common types for cloud infrastructure scanning
//!
//! This module defines the core data structures used across all cloud providers
//! (AWS, Azure, GCP) for representing resources, findings, and scan configurations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "aws"),
            CloudProvider::Azure => write!(f, "azure"),
            CloudProvider::Gcp => write!(f, "gcp"),
        }
    }
}

impl std::str::FromStr for CloudProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(CloudProvider::Aws),
            "azure" => Ok(CloudProvider::Azure),
            "gcp" => Ok(CloudProvider::Gcp),
            _ => Err(format!("Unknown cloud provider: {}", s)),
        }
    }
}

/// Types of cloud resources that can be scanned
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudResourceType {
    // AWS Resources
    Ec2Instance,
    SecurityGroup,
    S3Bucket,
    RdsInstance,
    IamUser,
    IamRole,
    IamPolicy,
    Lambda,
    ElasticIp,
    Vpc,
    Subnet,
    InternetGateway,
    NatGateway,
    EbsVolume,
    EksCluster,

    // Azure Resources
    VirtualMachine,
    NetworkSecurityGroup,
    StorageAccount,
    BlobContainer,
    SqlServer,
    SqlDatabase,
    KeyVault,
    ResourceGroup,
    VirtualNetwork,
    AppService,

    // GCP Resources
    ComputeInstance,
    FirewallRule,
    CloudStorage,
    CloudSql,
    ServiceAccount,
    IamBinding,
    GkeCluster,
    VpcNetwork,

    // Generic
    Other(String),
}

impl std::fmt::Display for CloudResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudResourceType::Ec2Instance => write!(f, "ec2_instance"),
            CloudResourceType::SecurityGroup => write!(f, "security_group"),
            CloudResourceType::S3Bucket => write!(f, "s3_bucket"),
            CloudResourceType::RdsInstance => write!(f, "rds_instance"),
            CloudResourceType::IamUser => write!(f, "iam_user"),
            CloudResourceType::IamRole => write!(f, "iam_role"),
            CloudResourceType::IamPolicy => write!(f, "iam_policy"),
            CloudResourceType::Lambda => write!(f, "lambda"),
            CloudResourceType::ElasticIp => write!(f, "elastic_ip"),
            CloudResourceType::Vpc => write!(f, "vpc"),
            CloudResourceType::Subnet => write!(f, "subnet"),
            CloudResourceType::InternetGateway => write!(f, "internet_gateway"),
            CloudResourceType::NatGateway => write!(f, "nat_gateway"),
            CloudResourceType::EbsVolume => write!(f, "ebs_volume"),
            CloudResourceType::EksCluster => write!(f, "eks_cluster"),
            CloudResourceType::VirtualMachine => write!(f, "virtual_machine"),
            CloudResourceType::NetworkSecurityGroup => write!(f, "network_security_group"),
            CloudResourceType::StorageAccount => write!(f, "storage_account"),
            CloudResourceType::BlobContainer => write!(f, "blob_container"),
            CloudResourceType::SqlServer => write!(f, "sql_server"),
            CloudResourceType::SqlDatabase => write!(f, "sql_database"),
            CloudResourceType::KeyVault => write!(f, "key_vault"),
            CloudResourceType::ResourceGroup => write!(f, "resource_group"),
            CloudResourceType::VirtualNetwork => write!(f, "virtual_network"),
            CloudResourceType::AppService => write!(f, "app_service"),
            CloudResourceType::ComputeInstance => write!(f, "compute_instance"),
            CloudResourceType::FirewallRule => write!(f, "firewall_rule"),
            CloudResourceType::CloudStorage => write!(f, "cloud_storage"),
            CloudResourceType::CloudSql => write!(f, "cloud_sql"),
            CloudResourceType::ServiceAccount => write!(f, "service_account"),
            CloudResourceType::IamBinding => write!(f, "iam_binding"),
            CloudResourceType::GkeCluster => write!(f, "gke_cluster"),
            CloudResourceType::VpcNetwork => write!(f, "vpc_network"),
            CloudResourceType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Cloud scan types - categories of resources to scan
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudScanType {
    /// IAM - Users, roles, policies, service accounts
    Iam,
    /// Storage - S3, Blob storage, Cloud Storage
    Storage,
    /// Compute - EC2, VMs, Compute Engine
    Compute,
    /// Network - Security groups, firewalls, VPCs
    Network,
    /// Database - RDS, SQL Server, Cloud SQL
    Database,
    /// All scan types
    All,
}

impl std::fmt::Display for CloudScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudScanType::Iam => write!(f, "iam"),
            CloudScanType::Storage => write!(f, "storage"),
            CloudScanType::Compute => write!(f, "compute"),
            CloudScanType::Network => write!(f, "network"),
            CloudScanType::Database => write!(f, "database"),
            CloudScanType::All => write!(f, "all"),
        }
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "info"),
            FindingSeverity::Low => write!(f, "low"),
            FindingSeverity::Medium => write!(f, "medium"),
            FindingSeverity::High => write!(f, "high"),
            FindingSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Ok(FindingSeverity::Info),
            "low" => Ok(FindingSeverity::Low),
            "medium" | "moderate" => Ok(FindingSeverity::Medium),
            "high" => Ok(FindingSeverity::High),
            "critical" => Ok(FindingSeverity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Type of finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    /// Configuration issue
    Misconfiguration,
    /// Known vulnerability
    Vulnerability,
    /// Exposed resource
    Exposure,
    /// Policy violation
    PolicyViolation,
    /// Best practice deviation
    BestPractice,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::Misconfiguration => write!(f, "misconfiguration"),
            FindingType::Vulnerability => write!(f, "vulnerability"),
            FindingType::Exposure => write!(f, "exposure"),
            FindingType::PolicyViolation => write!(f, "policy_violation"),
            FindingType::BestPractice => write!(f, "best_practice"),
        }
    }
}

/// Compliance framework mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub framework: String,
    pub control_id: String,
    pub control_title: Option<String>,
}

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    /// Description of what was found
    pub description: String,
    /// Raw data/config that shows the issue
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<serde_json::Value>,
    /// Expected value/configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// Actual value/configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    /// Timestamp when evidence was collected
    pub collected_at: DateTime<Utc>,
}

/// A discovered cloud resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    /// Internal ID for this resource
    pub id: String,
    /// Provider-specific resource ID
    pub resource_id: String,
    /// Type of resource
    pub resource_type: CloudResourceType,
    /// Cloud provider
    pub provider: CloudProvider,
    /// Region/location
    pub region: Option<String>,
    /// Resource name
    pub name: Option<String>,
    /// ARN (AWS), Resource ID (Azure), Self-link (GCP)
    pub arn: Option<String>,
    /// Resource tags/labels
    pub tags: HashMap<String, String>,
    /// Provider-specific metadata
    pub metadata: serde_json::Value,
    /// Current state (running, stopped, etc.)
    pub state: Option<String>,
    /// When this resource was discovered
    pub discovered_at: DateTime<Utc>,
}

/// A security finding for a cloud resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudFinding {
    /// Internal ID
    pub id: String,
    /// Scan ID this finding belongs to
    pub scan_id: String,
    /// Resource ID (if associated with a specific resource)
    pub resource_id: Option<String>,
    /// Type of finding
    pub finding_type: FindingType,
    /// Severity level
    pub severity: FindingSeverity,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Recommended remediation steps
    pub remediation: Option<String>,
    /// Compliance framework mappings
    pub compliance_mappings: Vec<ComplianceMapping>,
    /// ARN of the affected resource
    pub affected_resource_arn: Option<String>,
    /// Evidence supporting this finding
    pub evidence: Option<FindingEvidence>,
    /// Finding status
    pub status: FindingStatus,
    /// When this finding was created
    pub created_at: DateTime<Utc>,
}

/// Status of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Resolved,
    FalsePositive,
    Accepted,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Open => write!(f, "open"),
            FindingStatus::Resolved => write!(f, "resolved"),
            FindingStatus::FalsePositive => write!(f, "false_positive"),
            FindingStatus::Accepted => write!(f, "accepted"),
        }
    }
}

impl std::str::FromStr for FindingStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(FindingStatus::Open),
            "resolved" => Ok(FindingStatus::Resolved),
            "false_positive" => Ok(FindingStatus::FalsePositive),
            "accepted" => Ok(FindingStatus::Accepted),
            _ => Err(format!("Unknown finding status: {}", s)),
        }
    }
}

/// Cloud scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for CloudScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudScanStatus::Pending => write!(f, "pending"),
            CloudScanStatus::Running => write!(f, "running"),
            CloudScanStatus::Completed => write!(f, "completed"),
            CloudScanStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for CloudScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(CloudScanStatus::Pending),
            "running" => Ok(CloudScanStatus::Running),
            "completed" => Ok(CloudScanStatus::Completed),
            "failed" => Ok(CloudScanStatus::Failed),
            _ => Err(format!("Unknown scan status: {}", s)),
        }
    }
}

/// Configuration for a cloud scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScanConfig {
    /// Provider to scan
    pub provider: CloudProvider,
    /// Regions to scan (empty = all available regions)
    pub regions: Vec<String>,
    /// Types of scans to perform
    pub scan_types: Vec<CloudScanType>,
    /// Credentials ID to use (references stored credentials)
    pub credentials_id: Option<String>,
}

/// A cloud scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub regions: Vec<String>,
    pub scan_types: Vec<CloudScanType>,
    pub status: CloudScanStatus,
    pub credentials_id: Option<String>,
    pub findings_count: i32,
    pub resources_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of a cloud scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScanSummary {
    pub id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub status: CloudScanStatus,
    pub findings_count: i32,
    pub resources_count: i32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Breakdown of findings by severity
    pub findings_by_severity: HashMap<String, i32>,
    /// Breakdown of resources by type
    pub resources_by_type: HashMap<String, i32>,
}

/// Results from a cloud scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScanResults {
    pub scan: CloudScan,
    pub resources: Vec<CloudResource>,
    pub findings: Vec<CloudFinding>,
    pub summary: CloudScanSummary,
}

/// Progress message for cloud scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScanProgress {
    pub scan_id: String,
    pub status: CloudScanStatus,
    pub phase: String,
    pub progress_percent: f32,
    pub current_region: Option<String>,
    pub current_resource_type: Option<String>,
    pub resources_discovered: i32,
    pub findings_discovered: i32,
    pub message: String,
}

/// Trait for cloud scanner implementations
#[async_trait::async_trait]
pub trait CloudScanner: Send + Sync {
    /// Get the provider this scanner handles
    fn provider(&self) -> CloudProvider;

    /// Scan IAM resources (users, roles, policies)
    async fn scan_iam(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)>;

    /// Scan storage resources (S3, Blob Storage, Cloud Storage)
    async fn scan_storage(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)>;

    /// Scan compute resources (EC2, VMs, Compute Engine)
    async fn scan_compute(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)>;

    /// Scan network resources (Security Groups, Firewalls, NSGs)
    async fn scan_network(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)>;

    /// Scan database resources (RDS, Azure SQL, Cloud SQL)
    async fn scan_database(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)>;

    /// Run all requested scan types
    async fn run_scan(&self, config: &CloudScanConfig) -> anyhow::Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut all_resources = Vec::new();
        let mut all_findings = Vec::new();

        let scan_types = if config.scan_types.contains(&CloudScanType::All) {
            vec![
                CloudScanType::Iam,
                CloudScanType::Storage,
                CloudScanType::Compute,
                CloudScanType::Network,
                CloudScanType::Database,
            ]
        } else {
            config.scan_types.clone()
        };

        for scan_type in scan_types {
            let (resources, findings) = match scan_type {
                CloudScanType::Iam => self.scan_iam(config).await?,
                CloudScanType::Storage => self.scan_storage(config).await?,
                CloudScanType::Compute => self.scan_compute(config).await?,
                CloudScanType::Network => self.scan_network(config).await?,
                CloudScanType::Database => self.scan_database(config).await?,
                CloudScanType::All => continue, // Already handled above
            };
            all_resources.extend(resources);
            all_findings.extend(findings);
        }

        Ok((all_resources, all_findings))
    }
}
