//! Kubernetes Security Platform (KSP)
//!
//! Comprehensive Kubernetes security scanning, runtime protection, and compliance

#![allow(dead_code)]

pub mod cluster;
pub mod compliance;
pub mod network;
pub mod runtime;
pub mod types;
pub mod workloads;

pub use types::*;
use anyhow::Result;
use cluster::ClusterScanner;
use compliance::K8sComplianceScanner;
use network::NetworkScanner;
use runtime::RuntimeMonitor;
use workloads::WorkloadScanner;

/// Kubernetes security scanner configuration
#[derive(Debug, Clone)]
pub struct K8sScannerConfig {
    /// Path to kubeconfig file (defaults to ~/.kube/config)
    pub kubeconfig_path: Option<String>,
    /// Kubernetes context to use
    pub context: Option<String>,
    /// Namespace to scan (None for all namespaces)
    pub namespace: Option<String>,
    /// Enable runtime monitoring
    pub runtime_monitoring: bool,
    /// Enable compliance scanning
    pub compliance_scanning: bool,
}

impl Default for K8sScannerConfig {
    fn default() -> Self {
        Self {
            kubeconfig_path: None,
            context: None,
            namespace: None,
            runtime_monitoring: true,
            compliance_scanning: true,
        }
    }
}

/// Kubernetes security scanner
pub struct K8sSecurityScanner {
    /// Scanner configuration
    config: K8sScannerConfig,
    /// Cluster scanner
    cluster_scanner: ClusterScanner,
    /// Workload scanner
    workload_scanner: WorkloadScanner,
    /// Network scanner
    network_scanner: NetworkScanner,
    /// Runtime monitor
    runtime_monitor: RuntimeMonitor,
    /// Compliance scanner
    compliance_scanner: K8sComplianceScanner,
}

impl K8sSecurityScanner {
    pub fn new() -> Self {
        Self::with_config(K8sScannerConfig::default())
    }

    pub fn with_config(config: K8sScannerConfig) -> Self {
        Self {
            config: config.clone(),
            cluster_scanner: ClusterScanner::with_config(config.kubeconfig_path.clone(), config.context.clone()),
            workload_scanner: WorkloadScanner::with_config(config.kubeconfig_path.clone(), config.context.clone(), config.namespace.clone()),
            network_scanner: NetworkScanner::with_config(config.kubeconfig_path.clone(), config.context.clone(), config.namespace.clone()),
            runtime_monitor: RuntimeMonitor::with_config(config.kubeconfig_path.clone(), config.context.clone(), config.namespace.clone()),
            compliance_scanner: K8sComplianceScanner::with_config(config.kubeconfig_path.clone(), config.context.clone()),
        }
    }

    /// Perform comprehensive K8s security scan
    pub async fn scan(&self) -> Result<K8sSecurityReport> {
        let mut report = K8sSecurityReport::default();

        // Scan cluster-level security (RBAC, API server, secrets management)
        let cluster_findings = self.cluster_scanner.scan_all().await?;
        report.cluster_findings = cluster_findings;

        // Scan workload security (pods, containers, images)
        let workload_findings = self.workload_scanner.scan_all().await?;
        report.workload_findings = workload_findings;

        // Scan network policies and service mesh
        let network_findings = self.network_scanner.scan_all().await?;
        report.network_findings = network_findings;

        // Run runtime monitoring if enabled
        if self.config.runtime_monitoring {
            let runtime_findings = self.runtime_monitor.monitor_all().await?;
            report.runtime_findings = runtime_findings;
        }

        // Run compliance scanning if enabled
        if self.config.compliance_scanning {
            let compliance_findings = self.compliance_scanner.scan_all().await?;
            // Calculate compliance score based on findings
            let total_checks = compliance_findings.len();
            let passed_checks = compliance_findings.iter()
                .filter(|f| f.severity == "info" || f.severity == "low")
                .count();
            report.compliance_score = if total_checks > 0 {
                (passed_checks as f64 / total_checks as f64) * 100.0
            } else {
                100.0
            };
            // Add compliance findings to cluster findings
            report.cluster_findings.extend(compliance_findings);
        }

        Ok(report)
    }
}

impl Default for K8sSecurityScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct K8sSecurityReport {
    pub cluster_findings: Vec<K8sFinding>,
    pub workload_findings: Vec<K8sFinding>,
    pub network_findings: Vec<K8sFinding>,
    pub runtime_findings: Vec<K8sFinding>,
    pub compliance_score: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct K8sFinding {
    pub resource_type: String,
    pub resource_name: String,
    pub namespace: String,
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
}
