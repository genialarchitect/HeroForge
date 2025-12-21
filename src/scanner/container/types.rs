#![allow(dead_code)]
//! Container and Kubernetes scanning type definitions
//!
//! This module defines the core data structures used for container security scanning,
//! including Docker image analysis, Dockerfile security checks, and Kubernetes manifest scanning.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Container Scan Types
// ============================================================================

/// Type of container scan to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerScanType {
    /// Scan Docker image for vulnerabilities
    DockerImage,
    /// Analyze Dockerfile for security issues
    Dockerfile,
    /// Scan running container for configuration issues
    ContainerRuntime,
    /// Analyze Kubernetes manifests
    K8sManifest,
    /// Assess Kubernetes cluster security
    K8sCluster,
    /// All scan types
    All,
}

impl std::fmt::Display for ContainerScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerScanType::DockerImage => write!(f, "docker_image"),
            ContainerScanType::Dockerfile => write!(f, "dockerfile"),
            ContainerScanType::ContainerRuntime => write!(f, "container_runtime"),
            ContainerScanType::K8sManifest => write!(f, "k8s_manifest"),
            ContainerScanType::K8sCluster => write!(f, "k8s_cluster"),
            ContainerScanType::All => write!(f, "all"),
        }
    }
}

impl std::str::FromStr for ContainerScanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker_image" | "image" => Ok(ContainerScanType::DockerImage),
            "dockerfile" => Ok(ContainerScanType::Dockerfile),
            "container_runtime" | "runtime" => Ok(ContainerScanType::ContainerRuntime),
            "k8s_manifest" | "manifest" => Ok(ContainerScanType::K8sManifest),
            "k8s_cluster" | "cluster" => Ok(ContainerScanType::K8sCluster),
            "all" => Ok(ContainerScanType::All),
            _ => Err(format!("Unknown container scan type: {}", s)),
        }
    }
}

/// Container scan status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for ContainerScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerScanStatus::Pending => write!(f, "pending"),
            ContainerScanStatus::Running => write!(f, "running"),
            ContainerScanStatus::Completed => write!(f, "completed"),
            ContainerScanStatus::Failed => write!(f, "failed"),
        }
    }
}

impl std::str::FromStr for ContainerScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ContainerScanStatus::Pending),
            "running" => Ok(ContainerScanStatus::Running),
            "completed" => Ok(ContainerScanStatus::Completed),
            "failed" => Ok(ContainerScanStatus::Failed),
            _ => Err(format!("Unknown scan status: {}", s)),
        }
    }
}

/// Severity levels for container findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ContainerFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ContainerFindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerFindingSeverity::Info => write!(f, "info"),
            ContainerFindingSeverity::Low => write!(f, "low"),
            ContainerFindingSeverity::Medium => write!(f, "medium"),
            ContainerFindingSeverity::High => write!(f, "high"),
            ContainerFindingSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for ContainerFindingSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" | "informational" => Ok(ContainerFindingSeverity::Info),
            "low" => Ok(ContainerFindingSeverity::Low),
            "medium" | "moderate" => Ok(ContainerFindingSeverity::Medium),
            "high" => Ok(ContainerFindingSeverity::High),
            "critical" => Ok(ContainerFindingSeverity::Critical),
            _ => Err(format!("Unknown severity: {}", s)),
        }
    }
}

/// Type of container finding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFindingType {
    /// CVE vulnerability in image layer
    Vulnerability,
    /// Dockerfile best practice violation
    BestPractice,
    /// Security misconfiguration
    Misconfiguration,
    /// Secrets or sensitive data exposed
    SecretExposure,
    /// Privilege escalation risk
    PrivilegeEscalation,
    /// Network exposure issue
    NetworkExposure,
    /// Policy violation
    PolicyViolation,
    /// Outdated or deprecated component
    Outdated,
}

impl std::fmt::Display for ContainerFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerFindingType::Vulnerability => write!(f, "vulnerability"),
            ContainerFindingType::BestPractice => write!(f, "best_practice"),
            ContainerFindingType::Misconfiguration => write!(f, "misconfiguration"),
            ContainerFindingType::SecretExposure => write!(f, "secret_exposure"),
            ContainerFindingType::PrivilegeEscalation => write!(f, "privilege_escalation"),
            ContainerFindingType::NetworkExposure => write!(f, "network_exposure"),
            ContainerFindingType::PolicyViolation => write!(f, "policy_violation"),
            ContainerFindingType::Outdated => write!(f, "outdated"),
        }
    }
}

// ============================================================================
// Docker Image Types
// ============================================================================

/// Configuration for container scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanConfig {
    /// Name of the scan
    pub name: String,
    /// Types of scans to perform
    pub scan_types: Vec<ContainerScanType>,
    /// Docker image references to scan (e.g., "nginx:latest", "registry.io/app:v1")
    #[serde(default)]
    pub images: Vec<String>,
    /// Container registry URL (optional)
    pub registry_url: Option<String>,
    /// Registry username
    pub registry_username: Option<String>,
    /// Registry password (will be encrypted)
    pub registry_password: Option<String>,
    /// Dockerfile content to analyze
    pub dockerfile_content: Option<String>,
    /// K8s manifest content (YAML)
    pub manifest_content: Option<String>,
    /// Kubernetes context name (for cluster scanning)
    pub k8s_context: Option<String>,
    /// Kubernetes namespace (default: all namespaces)
    pub k8s_namespace: Option<String>,
    /// Whether to use demo mode with mock data
    #[serde(default)]
    pub demo_mode: bool,
    /// CRM customer reference
    pub customer_id: Option<String>,
    /// CRM engagement reference
    pub engagement_id: Option<String>,
}

/// Discovered Docker image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerImage {
    /// Unique ID
    pub id: String,
    /// Scan ID this image belongs to
    pub scan_id: String,
    /// Full image reference (e.g., "nginx:1.21.0")
    pub image_ref: String,
    /// Image digest (SHA256)
    pub digest: Option<String>,
    /// Registry URL
    pub registry: Option<String>,
    /// Repository name
    pub repository: String,
    /// Image tag
    pub tag: String,
    /// OS of the image
    pub os: Option<String>,
    /// Architecture
    pub architecture: Option<String>,
    /// Image creation date
    pub created: Option<DateTime<Utc>>,
    /// Image size in bytes
    pub size_bytes: Option<i64>,
    /// Number of layers
    pub layer_count: i32,
    /// Image labels
    pub labels: HashMap<String, String>,
    /// Number of vulnerabilities found
    pub vuln_count: i32,
    /// Number of critical vulnerabilities
    pub critical_count: i32,
    /// Number of high vulnerabilities
    pub high_count: i32,
    /// Discovered at
    pub discovered_at: DateTime<Utc>,
}

/// Image layer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageLayer {
    /// Layer ID
    pub id: String,
    /// Image ID this layer belongs to
    pub image_id: String,
    /// Layer digest
    pub digest: String,
    /// Layer size in bytes
    pub size_bytes: i64,
    /// Created by command
    pub created_by: Option<String>,
    /// Layer order (0 = base)
    pub order: i32,
    /// Is this an empty layer?
    pub empty: bool,
}

/// Package found in an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePackage {
    /// Package ID
    pub id: String,
    /// Image ID
    pub image_id: String,
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package type (apk, apt, npm, pip, gem, etc.)
    pub package_type: String,
    /// Layer where package was installed
    pub layer_id: Option<String>,
    /// License
    pub license: Option<String>,
    /// Source package
    pub source: Option<String>,
}

// ============================================================================
// Kubernetes Types
// ============================================================================

/// Kubernetes resource types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum K8sResourceType {
    Pod,
    Deployment,
    StatefulSet,
    DaemonSet,
    ReplicaSet,
    Job,
    CronJob,
    Service,
    Ingress,
    ConfigMap,
    Secret,
    ServiceAccount,
    Role,
    ClusterRole,
    RoleBinding,
    ClusterRoleBinding,
    NetworkPolicy,
    PodSecurityPolicy,
    Namespace,
    Node,
    PersistentVolume,
    PersistentVolumeClaim,
    Other(String),
}

impl std::fmt::Display for K8sResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            K8sResourceType::Pod => write!(f, "pod"),
            K8sResourceType::Deployment => write!(f, "deployment"),
            K8sResourceType::StatefulSet => write!(f, "statefulset"),
            K8sResourceType::DaemonSet => write!(f, "daemonset"),
            K8sResourceType::ReplicaSet => write!(f, "replicaset"),
            K8sResourceType::Job => write!(f, "job"),
            K8sResourceType::CronJob => write!(f, "cronjob"),
            K8sResourceType::Service => write!(f, "service"),
            K8sResourceType::Ingress => write!(f, "ingress"),
            K8sResourceType::ConfigMap => write!(f, "configmap"),
            K8sResourceType::Secret => write!(f, "secret"),
            K8sResourceType::ServiceAccount => write!(f, "serviceaccount"),
            K8sResourceType::Role => write!(f, "role"),
            K8sResourceType::ClusterRole => write!(f, "clusterrole"),
            K8sResourceType::RoleBinding => write!(f, "rolebinding"),
            K8sResourceType::ClusterRoleBinding => write!(f, "clusterrolebinding"),
            K8sResourceType::NetworkPolicy => write!(f, "networkpolicy"),
            K8sResourceType::PodSecurityPolicy => write!(f, "podsecuritypolicy"),
            K8sResourceType::Namespace => write!(f, "namespace"),
            K8sResourceType::Node => write!(f, "node"),
            K8sResourceType::PersistentVolume => write!(f, "persistentvolume"),
            K8sResourceType::PersistentVolumeClaim => write!(f, "persistentvolumeclaim"),
            K8sResourceType::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Kubernetes resource discovered during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sResource {
    /// Unique ID
    pub id: String,
    /// Scan ID
    pub scan_id: String,
    /// Resource type
    pub resource_type: K8sResourceType,
    /// API version
    pub api_version: String,
    /// Resource name
    pub name: String,
    /// Namespace (None for cluster-scoped resources)
    pub namespace: Option<String>,
    /// Resource labels
    pub labels: HashMap<String, String>,
    /// Resource annotations
    pub annotations: HashMap<String, String>,
    /// Full resource manifest (JSON)
    pub manifest: serde_json::Value,
    /// Number of findings for this resource
    pub finding_count: i32,
    /// Discovered at
    pub discovered_at: DateTime<Utc>,
}

// ============================================================================
// Finding Types
// ============================================================================

/// Security finding from container scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerFinding {
    /// Unique ID
    pub id: String,
    /// Scan ID
    pub scan_id: String,
    /// Image ID (if applicable)
    pub image_id: Option<String>,
    /// K8s resource ID (if applicable)
    pub resource_id: Option<String>,
    /// Finding type
    pub finding_type: ContainerFindingType,
    /// Severity level
    pub severity: ContainerFindingSeverity,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// CVE ID (if vulnerability)
    pub cve_id: Option<String>,
    /// CVSS score
    pub cvss_score: Option<f64>,
    /// CWE IDs
    pub cwe_ids: Vec<String>,
    /// Affected package name
    pub package_name: Option<String>,
    /// Affected package version
    pub package_version: Option<String>,
    /// Fixed in version
    pub fixed_version: Option<String>,
    /// File path (for Dockerfile/manifest findings)
    pub file_path: Option<String>,
    /// Line number
    pub line_number: Option<i32>,
    /// Remediation steps
    pub remediation: Option<String>,
    /// External references
    pub references: Vec<String>,
    /// Finding status
    pub status: FindingStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// Finding status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Resolved,
    FalsePositive,
    Accepted,
    InProgress,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Open => write!(f, "open"),
            FindingStatus::Resolved => write!(f, "resolved"),
            FindingStatus::FalsePositive => write!(f, "false_positive"),
            FindingStatus::Accepted => write!(f, "accepted"),
            FindingStatus::InProgress => write!(f, "in_progress"),
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
            "in_progress" => Ok(FindingStatus::InProgress),
            _ => Err(format!("Unknown finding status: {}", s)),
        }
    }
}

// ============================================================================
// Scan Records
// ============================================================================

/// Container scan record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScan {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub scan_types: Vec<ContainerScanType>,
    pub status: ContainerScanStatus,
    pub images_count: i32,
    pub resources_count: i32,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub customer_id: Option<String>,
    pub engagement_id: Option<String>,
}

/// Summary of a container scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanSummary {
    pub id: String,
    pub name: String,
    pub status: ContainerScanStatus,
    pub scan_types: Vec<ContainerScanType>,
    pub images_count: i32,
    pub resources_count: i32,
    pub findings_count: i32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// Breakdown of findings by severity
    pub findings_by_severity: HashMap<String, i32>,
    /// Breakdown of findings by type
    pub findings_by_type: HashMap<String, i32>,
    /// Top vulnerable images
    pub top_vulnerable_images: Vec<ImageVulnSummary>,
}

/// Vulnerability summary for an image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVulnSummary {
    pub image_ref: String,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

/// Results from a container scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResults {
    pub scan: ContainerScan,
    pub images: Vec<ContainerImage>,
    pub resources: Vec<K8sResource>,
    pub findings: Vec<ContainerFinding>,
    pub summary: ContainerScanSummary,
}

// ============================================================================
// Dockerfile Analysis Types
// ============================================================================

/// Dockerfile instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerfileInstruction {
    /// Line number
    pub line: i32,
    /// Instruction type (FROM, RUN, COPY, etc.)
    pub instruction: String,
    /// Instruction arguments
    pub arguments: String,
    /// Original line content
    pub original: String,
}

/// Dockerfile analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerfileAnalysis {
    /// Base image used
    pub base_image: Option<String>,
    /// Base image tag
    pub base_image_tag: Option<String>,
    /// All instructions parsed
    pub instructions: Vec<DockerfileInstruction>,
    /// Exposed ports
    pub exposed_ports: Vec<u16>,
    /// Environment variables (name only, not values for security)
    pub env_vars: Vec<String>,
    /// Volumes defined
    pub volumes: Vec<String>,
    /// User specified
    pub user: Option<String>,
    /// Workdir
    pub workdir: Option<String>,
    /// Entrypoint
    pub entrypoint: Option<String>,
    /// Cmd
    pub cmd: Option<String>,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Security findings
    pub findings: Vec<ContainerFinding>,
}

// ============================================================================
// K8s Manifest Analysis Types
// ============================================================================

/// Kubernetes manifest analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sManifestAnalysis {
    /// Resources found in manifest
    pub resources: Vec<K8sResource>,
    /// Security findings
    pub findings: Vec<ContainerFinding>,
    /// Manifest kind summary
    pub resource_counts: HashMap<String, i32>,
    /// Namespaces found
    pub namespaces: Vec<String>,
}

// ============================================================================
// Container Scanner Trait
// ============================================================================

/// Trait for container scanner implementations
#[async_trait::async_trait]
pub trait ContainerScanner: Send + Sync {
    /// Scan Docker images for vulnerabilities
    async fn scan_images(
        &self,
        config: &ContainerScanConfig,
    ) -> anyhow::Result<(Vec<ContainerImage>, Vec<ContainerFinding>)>;

    /// Analyze Dockerfile for security issues
    async fn analyze_dockerfile(
        &self,
        content: &str,
    ) -> anyhow::Result<DockerfileAnalysis>;

    /// Scan running containers
    async fn scan_runtime(
        &self,
        config: &ContainerScanConfig,
    ) -> anyhow::Result<Vec<ContainerFinding>>;

    /// Analyze Kubernetes manifests
    async fn analyze_manifest(
        &self,
        content: &str,
    ) -> anyhow::Result<K8sManifestAnalysis>;

    /// Scan Kubernetes cluster
    async fn scan_cluster(
        &self,
        config: &ContainerScanConfig,
    ) -> anyhow::Result<(Vec<K8sResource>, Vec<ContainerFinding>)>;
}
