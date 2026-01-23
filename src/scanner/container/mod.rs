#![allow(dead_code)]
//! Container and Kubernetes Security Scanning Module
//!
//! This module provides comprehensive security scanning capabilities for:
//! - Docker images (vulnerability detection in layers)
//! - Dockerfiles (security best practices, secrets, privileged mode)
//! - Container runtime (exposed ports, volumes, capabilities)
//! - Kubernetes manifests (RBAC, network policies, pod security)
//! - Kubernetes cluster assessment (if kubectl access available)
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scanner::container::{run_container_scan, ContainerScanConfig, ContainerScanType};
//!
//! let config = ContainerScanConfig {
//!     name: "My Container Scan".to_string(),
//!     scan_types: vec![ContainerScanType::DockerImage],
//!     images: vec!["nginx:latest".to_string()],
//!     ..Default::default()
//! };
//!
//! let results = run_container_scan(&config).await?;
//! ```

pub mod dockerfile;
pub mod image;
pub mod k8s_cis_benchmark;
pub mod k8s_cluster;
pub mod k8s_manifest;
pub mod k8s_network_policy;
pub mod k8s_pss;
pub mod k8s_rbac_analyzer;
pub mod runtime;
pub mod types;

// Re-export commonly used types
pub use types::{
    ContainerFinding,
    ContainerFindingSeverity,
    ContainerFindingType,
    ContainerImage,
    ContainerScan,
    ContainerScanConfig,
    ContainerScanStatus,
    ContainerScanSummary,
    ContainerScanType,
    ContainerScanner,
    DockerfileAnalysis,
    FindingStatus,
    ImageVulnSummary,
    K8sManifestAnalysis,
    K8sResource,
    K8sResourceType,
};

use anyhow::Result;
use std::collections::HashMap;

/// Run a container scan with the given configuration
///
/// This function orchestrates the scanning based on the requested scan types.
pub async fn run_container_scan(
    config: &ContainerScanConfig,
) -> Result<(Vec<ContainerImage>, Vec<K8sResource>, Vec<ContainerFinding>)> {
    log::info!("Starting container scan");

    let scanner = DefaultContainerScanner::new();
    let mut all_images = Vec::new();
    let mut all_resources = Vec::new();
    let mut all_findings = Vec::new();

    // Determine which scan types to run
    let scan_types = if config.scan_types.contains(&ContainerScanType::All) {
        vec![
            ContainerScanType::DockerImage,
            ContainerScanType::Dockerfile,
            ContainerScanType::ContainerRuntime,
            ContainerScanType::K8sManifest,
            ContainerScanType::K8sCluster,
        ]
    } else {
        config.scan_types.clone()
    };

    for scan_type in scan_types {
        match scan_type {
            ContainerScanType::DockerImage => {
                if !config.images.is_empty() {
                    log::info!("Scanning Docker images...");
                    let (images, findings) = scanner.scan_images(config).await?;
                    all_images.extend(images);
                    all_findings.extend(findings);
                }
            }
            ContainerScanType::Dockerfile => {
                if let Some(content) = &config.dockerfile_content {
                    log::info!("Analyzing Dockerfile...");
                    let analysis = scanner.analyze_dockerfile(content).await?;
                    all_findings.extend(analysis.findings);
                }
            }
            ContainerScanType::ContainerRuntime => {
                log::info!("Scanning container runtime...");
                let findings = scanner.scan_runtime(config).await?;
                all_findings.extend(findings);
            }
            ContainerScanType::K8sManifest => {
                if let Some(content) = &config.manifest_content {
                    log::info!("Analyzing Kubernetes manifest...");
                    let analysis = scanner.analyze_manifest(content).await?;
                    all_resources.extend(analysis.resources);
                    all_findings.extend(analysis.findings);
                }
            }
            ContainerScanType::K8sCluster => {
                if config.k8s_context.is_some() {
                    log::info!("Scanning Kubernetes cluster...");
                    let (resources, findings) = scanner.scan_cluster(config).await?;
                    all_resources.extend(resources);
                    all_findings.extend(findings);
                }
            }
            ContainerScanType::All => {
                // Already handled above
            }
        }
    }

    log::info!(
        "Container scan completed: {} images, {} resources, {} findings",
        all_images.len(),
        all_resources.len(),
        all_findings.len()
    );

    Ok((all_images, all_resources, all_findings))
}

/// Calculate a summary from scan results
pub fn calculate_scan_summary(
    scan_id: &str,
    scan_name: &str,
    status: ContainerScanStatus,
    scan_types: &[ContainerScanType],
    images: &[ContainerImage],
    resources: &[K8sResource],
    findings: &[ContainerFinding],
) -> ContainerScanSummary {
    // Calculate findings by severity
    let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
    for finding in findings {
        let severity = finding.severity.to_string();
        *findings_by_severity.entry(severity).or_insert(0) += 1;
    }

    // Calculate findings by type
    let mut findings_by_type: HashMap<String, i32> = HashMap::new();
    for finding in findings {
        let finding_type = finding.finding_type.to_string();
        *findings_by_type.entry(finding_type).or_insert(0) += 1;
    }

    // Calculate top vulnerable images
    let mut image_vulns: HashMap<String, ImageVulnSummary> = HashMap::new();
    for finding in findings {
        if let Some(image_id) = &finding.image_id {
            // Find the image reference
            let image_ref = images
                .iter()
                .find(|i| &i.id == image_id)
                .map(|i| i.image_ref.clone())
                .unwrap_or_else(|| image_id.clone());

            let entry = image_vulns.entry(image_ref.clone()).or_insert(ImageVulnSummary {
                image_ref,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            });

            match finding.severity {
                ContainerFindingSeverity::Critical => entry.critical += 1,
                ContainerFindingSeverity::High => entry.high += 1,
                ContainerFindingSeverity::Medium => entry.medium += 1,
                ContainerFindingSeverity::Low | ContainerFindingSeverity::Info => entry.low += 1,
            }
        }
    }

    let mut top_vulnerable_images: Vec<ImageVulnSummary> = image_vulns.into_values().collect();
    top_vulnerable_images.sort_by(|a, b| {
        (b.critical, b.high, b.medium, b.low)
            .cmp(&(a.critical, a.high, a.medium, a.low))
    });
    top_vulnerable_images.truncate(5);

    ContainerScanSummary {
        id: scan_id.to_string(),
        name: scan_name.to_string(),
        status,
        scan_types: scan_types.to_vec(),
        images_count: images.len() as i32,
        resources_count: resources.len() as i32,
        findings_count: findings.len() as i32,
        created_at: chrono::Utc::now(),
        completed_at: Some(chrono::Utc::now()),
        findings_by_severity,
        findings_by_type,
        top_vulnerable_images,
    }
}

/// Default container scanner implementation
pub struct DefaultContainerScanner;

impl DefaultContainerScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ContainerScanner for DefaultContainerScanner {
    async fn scan_images(
        &self,
        config: &ContainerScanConfig,
    ) -> Result<(Vec<ContainerImage>, Vec<ContainerFinding>)> {
        image::scan_images(config).await
    }

    async fn analyze_dockerfile(
        &self,
        content: &str,
    ) -> Result<DockerfileAnalysis> {
        dockerfile::analyze_dockerfile(content).await
    }

    async fn scan_runtime(
        &self,
        config: &ContainerScanConfig,
    ) -> Result<Vec<ContainerFinding>> {
        runtime::scan_runtime(config).await
    }

    async fn analyze_manifest(
        &self,
        content: &str,
    ) -> Result<K8sManifestAnalysis> {
        k8s_manifest::analyze_manifest(content).await
    }

    async fn scan_cluster(
        &self,
        config: &ContainerScanConfig,
    ) -> Result<(Vec<K8sResource>, Vec<ContainerFinding>)> {
        k8s_cluster::scan_cluster(config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_container_scan() {
        let config = ContainerScanConfig {
            name: "Test Scan".to_string(),
            scan_types: vec![ContainerScanType::DockerImage],
            images: vec!["nginx:latest".to_string()],
            registry_url: None,
            registry_username: None,
            registry_password: None,
            dockerfile_content: None,
            manifest_content: None,
            k8s_context: None,
            k8s_namespace: None,
            customer_id: None,
            engagement_id: None,
        };

        // Real scan - results depend on trivy/grype/docker availability
        let result = run_container_scan(&config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_type_parsing() {
        assert_eq!(
            "docker_image".parse::<ContainerScanType>().unwrap(),
            ContainerScanType::DockerImage
        );
        assert_eq!(
            "k8s_manifest".parse::<ContainerScanType>().unwrap(),
            ContainerScanType::K8sManifest
        );
    }

    #[test]
    fn test_severity_ordering() {
        assert!(ContainerFindingSeverity::Critical > ContainerFindingSeverity::High);
        assert!(ContainerFindingSeverity::High > ContainerFindingSeverity::Medium);
        assert!(ContainerFindingSeverity::Medium > ContainerFindingSeverity::Low);
    }
}
