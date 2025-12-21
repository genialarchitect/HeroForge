//! Infrastructure-as-Code (IaC) Security Scanning Module
//!
//! This module provides comprehensive scanning capabilities for IaC files:
//! - Terraform HCL files
//! - AWS CloudFormation templates (JSON/YAML)
//! - Azure ARM templates
//!
//! # Usage
//!
//! ```rust,ignore
//! use heroforge::scanner::iac::{IacScanner, IacSource};
//!
//! let scanner = IacScanner::new();
//!
//! // Scan a single file
//! let response = scanner.analyze_content("main.tf", content)?;
//!
//! // Or run a full scan
//! let results = scanner.run_scan(&config).await?;
//! ```

pub mod arm;
pub mod cloudformation;
pub mod rules;
pub mod terraform;
pub mod types;

pub use arm::ArmScanner;
pub use cloudformation::CloudFormationScanner;
pub use rules::{get_builtin_iac_rules, get_builtin_rules, RuleMatcher};
pub use terraform::TerraformScanner;
pub use types::*;

use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Main IaC scanner that handles all IaC formats
pub struct IacScanner {
    terraform_scanner: TerraformScanner,
    cloudformation_scanner: CloudFormationScanner,
    arm_scanner: ArmScanner,
}

impl IacScanner {
    pub fn new() -> Self {
        Self {
            terraform_scanner: TerraformScanner::new(),
            cloudformation_scanner: CloudFormationScanner::new(),
            arm_scanner: ArmScanner::new(),
        }
    }

    /// Detect the platform of IaC content
    pub fn detect_platform(content: &str, filename: &str) -> Option<IacPlatform> {
        if TerraformScanner::is_terraform(content, filename) {
            Some(IacPlatform::Terraform)
        } else if CloudFormationScanner::is_cloudformation(content, filename) {
            Some(IacPlatform::CloudFormation)
        } else if ArmScanner::is_arm_template(content, filename) {
            Some(IacPlatform::AzureArm)
        } else {
            None
        }
    }

    /// Analyze content and return findings
    pub fn analyze_content(&self, filename: &str, content: &str) -> Result<AnalyzeFileResponse> {
        let platform = Self::detect_platform(content, filename)
            .ok_or_else(|| anyhow!("Unable to detect IaC platform for file: {}", filename))?;

        match platform {
            IacPlatform::Terraform => self.terraform_scanner.analyze_file(content, filename),
            IacPlatform::CloudFormation => self.cloudformation_scanner.analyze_file(content, filename),
            IacPlatform::AzureArm => self.arm_scanner.analyze_file(content, filename),
            _ => Err(anyhow!("Unsupported IaC platform: {:?}", platform)),
        }
    }

    /// Analyze content with a specific platform (for when platform is known)
    pub fn analyze_content_with_platform(
        &self,
        filename: &str,
        content: &str,
        platform: IacPlatform,
    ) -> Result<AnalyzeFileResponse> {
        match platform {
            IacPlatform::Terraform => self.terraform_scanner.analyze_file(content, filename),
            IacPlatform::CloudFormation => self.cloudformation_scanner.analyze_file(content, filename),
            IacPlatform::AzureArm => self.arm_scanner.analyze_file(content, filename),
            _ => Err(anyhow!("Unsupported IaC platform: {:?}", platform)),
        }
    }

    /// Scan multiple files and return aggregated results
    pub fn scan_files(&self, files: &[(String, String)]) -> Result<IacScanResults> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        let mut all_files = Vec::new();
        let mut all_findings = Vec::new();
        let mut platforms = Vec::new();
        let mut providers = Vec::new();

        for (filename, content) in files {
            let file_id = uuid::Uuid::new_v4().to_string();

            let platform = match Self::detect_platform(content, filename) {
                Some(p) => p,
                None => continue, // Skip unrecognized files
            };

            if !platforms.contains(&platform) {
                platforms.push(platform);
            }

            let (findings, file_resources, provider) = match platform {
                IacPlatform::Terraform => {
                    let resources = self.terraform_scanner.parse_resources(content, &file_id);
                    let findings = self.terraform_scanner.scan(content, filename, &scan_id, &file_id);
                    let provider = TerraformScanner::detect_provider(content);
                    (findings, resources, provider)
                }
                IacPlatform::CloudFormation => {
                    let template = CloudFormationScanner::parse_template(content)?;
                    let resources = self.cloudformation_scanner.parse_resources(&template, &file_id);
                    let findings = self.cloudformation_scanner.scan(content, filename, &scan_id, &file_id);
                    (findings, resources, IacCloudProvider::Aws)
                }
                IacPlatform::AzureArm => {
                    let template = ArmScanner::parse_template(content)?;
                    let resources = self.arm_scanner.parse_resources(&template, &file_id);
                    let findings = self.arm_scanner.scan(content, filename, &scan_id, &file_id);
                    (findings, resources, IacCloudProvider::Azure)
                }
                _ => continue,
            };

            if !providers.contains(&provider) {
                providers.push(provider);
            }

            let finding_count = findings.len() as i32;
            all_findings.extend(findings);

            let iac_file = IacFile {
                id: file_id,
                scan_id: scan_id.clone(),
                filename: filename.clone(),
                path: filename.clone(),
                content: Some(content.clone()),
                platform,
                provider,
                size_bytes: content.len() as i64,
                line_count: content.lines().count() as i32,
                resource_count: file_resources.len() as i32,
                finding_count,
                created_at: chrono::Utc::now(),
            };
            all_files.push(iac_file);
        }

        // Calculate severity counts
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
        let mut findings_by_category: HashMap<String, i32> = HashMap::new();
        let mut resources_by_type: HashMap<String, i32> = HashMap::new();

        for finding in &all_findings {
            match finding.severity {
                IacSeverity::Critical => critical_count += 1,
                IacSeverity::High => high_count += 1,
                IacSeverity::Medium => medium_count += 1,
                IacSeverity::Low => low_count += 1,
                IacSeverity::Info => info_count += 1,
            }
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;
            *findings_by_category
                .entry(finding.category.to_string())
                .or_insert(0) += 1;
            if let Some(ref rt) = finding.resource_type {
                *resources_by_type.entry(rt.to_string()).or_insert(0) += 1;
            }
        }

        let scan = IacScan {
            id: scan_id.clone(),
            user_id: String::new(), // Will be set by API layer
            name: String::new(),    // Will be set by API layer
            source_type: "upload".to_string(),
            source_url: None,
            platforms: platforms.clone(),
            providers: providers.clone(),
            status: IacScanStatus::Completed,
            file_count: all_files.len() as i32,
            resource_count: all_files.iter().map(|f| f.resource_count).sum(),
            finding_count: all_findings.len() as i32,
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
            error_message: None,
            created_at: chrono::Utc::now(),
            started_at: Some(chrono::Utc::now()),
            completed_at: Some(chrono::Utc::now()),
            customer_id: None,
            engagement_id: None,
        };

        let summary = IacScanSummary {
            id: scan_id,
            name: String::new(),
            status: IacScanStatus::Completed,
            platforms,
            file_count: all_files.len() as i32,
            finding_count: all_findings.len() as i32,
            findings_by_severity,
            findings_by_category,
            resources_by_type,
            created_at: chrono::Utc::now(),
            completed_at: Some(chrono::Utc::now()),
        };

        Ok(IacScanResults {
            scan,
            files: all_files,
            findings: all_findings,
            summary,
        })
    }
}

impl Default for IacScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Get file extension for a filename
fn get_extension(filename: &str) -> Option<&str> {
    std::path::Path::new(filename)
        .extension()
        .and_then(|ext| ext.to_str())
}

/// Check if a file is likely an IaC file based on extension
pub fn is_iac_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();

    // Terraform
    if lower.ends_with(".tf") || lower.ends_with(".tf.json") {
        return true;
    }

    // CloudFormation
    if lower.ends_with(".template")
        || lower.ends_with(".template.json")
        || lower.ends_with(".template.yaml")
        || lower.ends_with(".template.yml")
        || lower.contains("cloudformation")
    {
        return true;
    }

    // ARM
    if lower.ends_with(".arm.json")
        || lower.contains("azuredeploy")
        || lower.contains("maintemplate")
    {
        return true;
    }

    // Generic JSON/YAML that might be IaC
    if lower.ends_with(".json") || lower.ends_with(".yaml") || lower.ends_with(".yml") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform_terraform() {
        let content = r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"#;
        assert_eq!(
            IacScanner::detect_platform(content, "main.tf"),
            Some(IacPlatform::Terraform)
        );
    }

    #[test]
    fn test_detect_platform_cloudformation() {
        let content = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {}
        }"#;
        assert_eq!(
            IacScanner::detect_platform(content, "template.json"),
            Some(IacPlatform::CloudFormation)
        );
    }

    #[test]
    fn test_detect_platform_arm() {
        let content = r#"{
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": []
        }"#;
        assert_eq!(
            IacScanner::detect_platform(content, "template.json"),
            Some(IacPlatform::AzureArm)
        );
    }

    #[test]
    fn test_analyze_content() {
        let scanner = IacScanner::new();

        let terraform_content = r#"
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
"#;

        let result = scanner.analyze_content("main.tf", terraform_content).unwrap();
        assert_eq!(result.platform, IacPlatform::Terraform);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_scan_files() {
        let scanner = IacScanner::new();

        let files = vec![
            (
                "main.tf".to_string(),
                r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"#
                .to_string(),
            ),
            (
                "security.tf".to_string(),
                r#"
resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#
                .to_string(),
            ),
        ];

        let result = scanner.scan_files(&files).unwrap();
        assert_eq!(result.files.len(), 2);
        assert!(!result.findings.is_empty());
        assert!(result.scan.critical_count > 0 || result.scan.high_count > 0);
    }

    #[test]
    fn test_is_iac_file() {
        assert!(is_iac_file("main.tf"));
        assert!(is_iac_file("infrastructure.tf.json"));
        assert!(is_iac_file("template.template.json"));
        assert!(is_iac_file("cloudformation-stack.yaml"));
        assert!(is_iac_file("azuredeploy.json"));
        assert!(is_iac_file("mainTemplate.json"));
        assert!(!is_iac_file("README.md"));
        assert!(!is_iac_file("main.py"));
    }
}
