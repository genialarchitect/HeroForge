#![allow(dead_code)]
//! Cloud Infrastructure Scanning Module
//!
//! This module provides comprehensive scanning capabilities for major cloud providers:
//! - AWS (Amazon Web Services)
//! - Azure (Microsoft Azure)
//! - GCP (Google Cloud Platform)
//!
//! Each scanner checks for common security misconfigurations including:
//! - IAM/Identity issues (overly permissive roles, unused accounts, missing MFA)
//! - Storage security (public buckets, missing encryption)
//! - Compute security (instance metadata, security groups)
//! - Network exposure (open ports, unrestricted access)
//! - Database security (public access, missing encryption, no backups)
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scanner::cloud::{run_cloud_scan, CloudScanConfig, CloudProvider, CloudScanType};
//!
//! let config = CloudScanConfig {
//!     provider: CloudProvider::Aws,
//!     regions: vec!["us-east-1".to_string()],
//!     scan_types: vec![CloudScanType::All],
//!     credentials_id: None,
//! };
//!
//! let (resources, findings) = run_cloud_scan(&config).await?;
//! ```

pub mod aws;
pub mod azure;
pub mod cloud_discovery;
pub mod cspm;
pub mod gcp;
pub mod types;

// Re-export commonly used types
pub use types::{
    CloudFinding,
    CloudProvider,
    CloudResource,
    CloudResourceType,
    CloudScan,
    CloudScanConfig,
    CloudScanStatus,
    CloudScanSummary,
    CloudScanType,
    CloudScanner,
    ComplianceMapping,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    FindingType,
};

pub use aws::AwsScanner;
pub use azure::AzureScanner;
#[allow(unused_imports)]
pub use cloud_discovery::{
    check_bucket_names, run_cloud_discovery, AccessibilityStatus, CloudAsset, CloudAssetType,
    CloudDiscoveryConfig, CloudDiscoveryResult, CloudDiscoveryScanner, CloudDiscoveryStatus,
    CloudProviderType, DiscoveryMethod, DiscoveryStatistics,
};
pub use gcp::GcpScanner;

use anyhow::Result;
use std::collections::HashMap;

/// Run a cloud scan with the given configuration
///
/// This function creates the appropriate scanner based on the provider
/// in the configuration and runs the scan.
pub async fn run_cloud_scan(
    config: &CloudScanConfig,
) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
    log::info!(
        "Starting cloud scan for provider: {}",
        config.provider
    );

    let scanner: Box<dyn CloudScanner> = match config.provider {
        CloudProvider::Aws => Box::new(AwsScanner::new()),
        CloudProvider::Azure => Box::new(AzureScanner::new()),
        CloudProvider::Gcp => Box::new(GcpScanner::new()),
    };

    scanner.run_scan(config).await
}

/// Calculate a summary from scan results
pub fn calculate_scan_summary(
    scan_id: &str,
    scan_name: &str,
    provider: CloudProvider,
    status: CloudScanStatus,
    resources: &[CloudResource],
    findings: &[CloudFinding],
) -> CloudScanSummary {
    // Calculate findings by severity
    let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
    for finding in findings {
        let severity = finding.severity.to_string();
        *findings_by_severity.entry(severity).or_insert(0) += 1;
    }

    // Calculate resources by type
    let mut resources_by_type: HashMap<String, i32> = HashMap::new();
    for resource in resources {
        let resource_type = resource.resource_type.to_string();
        *resources_by_type.entry(resource_type).or_insert(0) += 1;
    }

    // Get the latest completed_at from findings
    let completed_at = findings.iter().map(|f| f.created_at).max();

    CloudScanSummary {
        id: scan_id.to_string(),
        name: scan_name.to_string(),
        provider,
        status,
        findings_count: findings.len() as i32,
        resources_count: resources.len() as i32,
        created_at: chrono::Utc::now(),
        completed_at,
        findings_by_severity,
        resources_by_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_cloud_scan_aws() {
        let config = CloudScanConfig {
            provider: CloudProvider::Aws,
            regions: vec!["us-east-1".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
        };

        // Real scan - results depend on AWS credentials being configured
        let result = run_cloud_scan(&config).await;
        // Without credentials, the AWS SDK will return an error
        if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_run_cloud_scan_azure() {
        let config = CloudScanConfig {
            provider: CloudProvider::Azure,
            regions: vec!["eastus".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
        };

        // Without Azure credentials, should return error
        if std::env::var("AZURE_SUBSCRIPTION_ID").is_err() {
            let result = run_cloud_scan(&config).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_run_cloud_scan_gcp() {
        let config = CloudScanConfig {
            provider: CloudProvider::Gcp,
            regions: vec!["us-central1".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
        };

        // Without GCP credentials, should return error
        if std::env::var("GCP_PROJECT_ID").is_err() {
            let result = run_cloud_scan(&config).await;
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_calculate_scan_summary() {
        let resources = vec![
            CloudResource {
                id: "1".to_string(),
                resource_id: "bucket1".to_string(),
                resource_type: CloudResourceType::S3Bucket,
                provider: CloudProvider::Aws,
                region: Some("us-east-1".to_string()),
                name: Some("test-bucket".to_string()),
                arn: None,
                tags: HashMap::new(),
                metadata: serde_json::json!({}),
                state: None,
                discovered_at: chrono::Utc::now(),
            },
            CloudResource {
                id: "2".to_string(),
                resource_id: "instance1".to_string(),
                resource_type: CloudResourceType::Ec2Instance,
                provider: CloudProvider::Aws,
                region: Some("us-east-1".to_string()),
                name: Some("test-instance".to_string()),
                arn: None,
                tags: HashMap::new(),
                metadata: serde_json::json!({}),
                state: None,
                discovered_at: chrono::Utc::now(),
            },
        ];

        let findings = vec![
            CloudFinding {
                id: "f1".to_string(),
                scan_id: "scan1".to_string(),
                resource_id: Some("1".to_string()),
                finding_type: FindingType::Misconfiguration,
                severity: FindingSeverity::Critical,
                title: "Test finding".to_string(),
                description: "Test".to_string(),
                remediation: None,
                compliance_mappings: vec![],
                affected_resource_arn: None,
                evidence: None,
                status: FindingStatus::Open,
                created_at: chrono::Utc::now(),
            },
            CloudFinding {
                id: "f2".to_string(),
                scan_id: "scan1".to_string(),
                resource_id: Some("2".to_string()),
                finding_type: FindingType::Exposure,
                severity: FindingSeverity::High,
                title: "Test finding 2".to_string(),
                description: "Test".to_string(),
                remediation: None,
                compliance_mappings: vec![],
                affected_resource_arn: None,
                evidence: None,
                status: FindingStatus::Open,
                created_at: chrono::Utc::now(),
            },
        ];

        let summary = calculate_scan_summary(
            "scan1",
            "Test Scan",
            CloudProvider::Aws,
            CloudScanStatus::Completed,
            &resources,
            &findings,
        );

        assert_eq!(summary.findings_count, 2);
        assert_eq!(summary.resources_count, 2);
        assert_eq!(summary.findings_by_severity.get("critical"), Some(&1));
        assert_eq!(summary.findings_by_severity.get("high"), Some(&1));
        assert_eq!(summary.resources_by_type.get("s3_bucket"), Some(&1));
        assert_eq!(summary.resources_by_type.get("ec2_instance"), Some(&1));
    }
}
