#![allow(dead_code)]
//! Terraform HCL parser and analyzer
//!
//! This module parses Terraform HCL files and extracts resources for security analysis.

use super::rules::{get_builtin_rules, RuleMatcher};
use super::types::*;
use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

lazy_static::lazy_static! {
    // Match Terraform resource blocks
    static ref RESOURCE_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)resource\s+"([^"]+)"\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match Terraform data blocks
    static ref DATA_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)data\s+"([^"]+)"\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match Terraform module blocks
    static ref MODULE_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)module\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match Terraform provider blocks
    static ref PROVIDER_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)provider\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match Terraform variable blocks
    static ref VARIABLE_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)variable\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match Terraform output blocks
    static ref OUTPUT_PATTERN: Regex = Regex::new(
        r#"(?m)^(?:\s*)output\s+"([^"]+)"\s*\{"#
    ).unwrap();

    // Match simple key = value pairs
    static ref ATTRIBUTE_PATTERN: Regex = Regex::new(
        r#"(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$"#
    ).unwrap();
}

/// Terraform-specific scanner
pub struct TerraformScanner {
    rules: Vec<Box<dyn RuleMatcher>>,
}

impl TerraformScanner {
    pub fn new() -> Self {
        Self {
            rules: get_builtin_rules(),
        }
    }

    pub fn with_custom_rules(custom_rules: Vec<Box<dyn RuleMatcher>>) -> Self {
        let mut rules = get_builtin_rules();
        rules.extend(custom_rules);
        Self { rules }
    }

    /// Detect if content is Terraform HCL
    pub fn is_terraform(content: &str, filename: &str) -> bool {
        let lower_filename = filename.to_lowercase();

        // Check file extension
        if lower_filename.ends_with(".tf") || lower_filename.ends_with(".tf.json") {
            return true;
        }

        // Check for Terraform-specific patterns in content
        if RESOURCE_PATTERN.is_match(content)
            || PROVIDER_PATTERN.is_match(content)
            || MODULE_PATTERN.is_match(content)
            || VARIABLE_PATTERN.is_match(content)
        {
            return true;
        }

        // Check for terraform {} block
        if content.contains("terraform {") || content.contains("terraform{") {
            return true;
        }

        false
    }

    /// Detect cloud provider from Terraform content
    pub fn detect_provider(content: &str) -> IacCloudProvider {
        let mut providers_found = Vec::new();

        // Check provider blocks
        for cap in PROVIDER_PATTERN.captures_iter(content) {
            let provider = cap.get(1).map_or("", |m| m.as_str()).to_lowercase();
            match provider.as_str() {
                "aws" => providers_found.push(IacCloudProvider::Aws),
                "azurerm" | "azure" => providers_found.push(IacCloudProvider::Azure),
                "google" | "google-beta" => providers_found.push(IacCloudProvider::Gcp),
                _ => {}
            }
        }

        // Check resource prefixes
        if content.contains("aws_") {
            providers_found.push(IacCloudProvider::Aws);
        }
        if content.contains("azurerm_") {
            providers_found.push(IacCloudProvider::Azure);
        }
        if content.contains("google_") {
            providers_found.push(IacCloudProvider::Gcp);
        }

        providers_found.dedup();

        match providers_found.len() {
            0 => IacCloudProvider::None,
            1 => providers_found[0],
            _ => IacCloudProvider::Multi,
        }
    }

    /// Parse resources from Terraform content
    pub fn parse_resources(&self, content: &str, file_id: &str) -> Vec<IacResource> {
        let mut resources = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for cap in RESOURCE_PATTERN.captures_iter(content) {
            let resource_type = cap.get(1).map_or("", |m| m.as_str());
            let resource_name = cap.get(2).map_or("", |m| m.as_str());

            // Find line number
            let match_start = cap.get(0).map_or(0, |m| m.start());
            let line_start = content[..match_start].lines().count() as i32 + 1;

            // Find matching closing brace
            let line_end = find_block_end(&lines, (line_start - 1) as usize);

            // Extract attributes
            let block_content = if line_end > (line_start - 1) as usize {
                lines[(line_start - 1) as usize..=line_end].join("\n")
            } else {
                String::new()
            };

            let attributes = parse_attributes(&block_content);

            let iac_resource_type = map_terraform_resource_type(resource_type);
            let provider = detect_provider_from_resource_type(resource_type);

            resources.push(IacResource {
                id: uuid::Uuid::new_v4().to_string(),
                file_id: file_id.to_string(),
                resource_type: iac_resource_type,
                resource_name: resource_name.to_string(),
                provider,
                line_start,
                line_end: (line_end + 1) as i32,
                attributes,
            });
        }

        resources
    }

    /// Scan Terraform content for security issues
    pub fn scan(&self, content: &str, filename: &str, scan_id: &str, file_id: &str) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        for rule in &self.rules {
            // Check if rule applies to Terraform
            if !rule.platforms().contains(&IacPlatform::Terraform) {
                continue;
            }

            let matches = rule.check(content, filename, IacPlatform::Terraform);

            for rule_match in matches {
                let finding = IacFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    file_id: file_id.to_string(),
                    rule_id: rule.id().to_string(),
                    severity: rule.severity(),
                    category: rule.category(),
                    title: rule.name().to_string(),
                    description: rule_match
                        .message
                        .unwrap_or_else(|| rule.description().to_string()),
                    resource_type: rule_match.resource_type,
                    resource_name: rule_match.resource_name,
                    line_start: rule_match.line_start,
                    line_end: rule_match.line_end,
                    code_snippet: Some(rule_match.code_snippet),
                    remediation: rule.remediation().to_string(),
                    documentation_url: rule.documentation_url().map(String::from),
                    compliance_mappings: rule.compliance_mappings().to_vec(),
                    status: IacFindingStatus::Open,
                    suppressed: false,
                    suppression_reason: None,
                    created_at: chrono::Utc::now(),
                };
                findings.push(finding);
            }
        }

        findings
    }

    /// Analyze a single Terraform file
    pub fn analyze_file(&self, content: &str, filename: &str) -> Result<AnalyzeFileResponse> {
        let file_id = uuid::Uuid::new_v4().to_string();
        let scan_id = uuid::Uuid::new_v4().to_string();

        let provider = Self::detect_provider(content);
        let resources = self.parse_resources(content, &file_id);
        let findings = self.scan(content, filename, &scan_id, &file_id);

        let line_count = content.lines().count() as i32;

        let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
        for finding in &findings {
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;
        }

        Ok(AnalyzeFileResponse {
            platform: IacPlatform::Terraform,
            provider,
            resources,
            findings,
            summary: FileSummary {
                line_count,
                resource_count: 0, // Will be filled from resources.len()
                finding_count: 0,  // Will be filled from findings.len()
                findings_by_severity,
            },
        })
    }
}

impl Default for TerraformScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Find the end of a block (matching closing brace)
fn find_block_end(lines: &[&str], start_line: usize) -> usize {
    let mut brace_count = 0;
    let mut in_block = false;

    for (i, line) in lines.iter().enumerate().skip(start_line) {
        for c in line.chars() {
            if c == '{' {
                brace_count += 1;
                in_block = true;
            } else if c == '}' {
                brace_count -= 1;
                if in_block && brace_count == 0 {
                    return i;
                }
            }
        }
    }

    lines.len().saturating_sub(1)
}

/// Parse simple attributes from a block
fn parse_attributes(content: &str) -> HashMap<String, Value> {
    let mut attributes = HashMap::new();

    for cap in ATTRIBUTE_PATTERN.captures_iter(content) {
        let key = cap.get(1).map_or("", |m| m.as_str());
        let value_str = cap.get(2).map_or("", |m| m.as_str()).trim();

        // Skip nested blocks
        if value_str == "{" || value_str.starts_with("{") && !value_str.ends_with("}") {
            continue;
        }

        let value = parse_hcl_value(value_str);
        attributes.insert(key.to_string(), value);
    }

    attributes
}

/// Parse an HCL value into JSON
fn parse_hcl_value(value_str: &str) -> Value {
    let trimmed = value_str.trim();

    // Boolean
    if trimmed == "true" {
        return Value::Bool(true);
    }
    if trimmed == "false" {
        return Value::Bool(false);
    }

    // Number
    if let Ok(n) = trimmed.parse::<i64>() {
        return Value::Number(n.into());
    }
    if let Ok(n) = trimmed.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(n) {
            return Value::Number(n);
        }
    }

    // String (quoted)
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        let unquoted = &trimmed[1..trimmed.len() - 1];
        return Value::String(unquoted.to_string());
    }

    // Array
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        let items: Vec<Value> = inner
            .split(',')
            .map(|s| parse_hcl_value(s.trim()))
            .collect();
        return Value::Array(items);
    }

    // Variable reference or other
    Value::String(trimmed.to_string())
}

/// Map Terraform resource type to IacResourceType
fn map_terraform_resource_type(resource_type: &str) -> IacResourceType {
    match resource_type {
        // AWS
        "aws_s3_bucket" => IacResourceType::AwsS3Bucket,
        "aws_iam_role" => IacResourceType::AwsIamRole,
        "aws_iam_policy" => IacResourceType::AwsIamPolicy,
        "aws_iam_user" => IacResourceType::AwsIamUser,
        "aws_instance" => IacResourceType::AwsEc2Instance,
        "aws_security_group" => IacResourceType::AwsSecurityGroup,
        "aws_db_instance" => IacResourceType::AwsRdsInstance,
        "aws_lambda_function" => IacResourceType::AwsLambdaFunction,
        "aws_kms_key" => IacResourceType::AwsKmsKey,
        "aws_ebs_volume" => IacResourceType::AwsEbsVolume,
        "aws_lb" | "aws_alb" | "aws_elb" => IacResourceType::AwsElb,
        "aws_sns_topic" => IacResourceType::AwsSns,
        "aws_sqs_queue" => IacResourceType::AwsSqs,
        "aws_cloudwatch_log_group" => IacResourceType::AwsCloudwatch,
        "aws_vpc" => IacResourceType::AwsVpc,
        "aws_subnet" => IacResourceType::AwsSubnet,
        "aws_eks_cluster" => IacResourceType::AwsEks,
        "aws_ecs_cluster" | "aws_ecs_service" => IacResourceType::AwsEcs,
        "aws_elasticache_cluster" => IacResourceType::AwsElasticache,
        "aws_dynamodb_table" => IacResourceType::AwsDynamodb,
        "aws_secretsmanager_secret" => IacResourceType::AwsSecretsManager,

        // Azure
        "azurerm_storage_account" => IacResourceType::AzureStorageAccount,
        "azurerm_storage_container" => IacResourceType::AzureBlobContainer,
        "azurerm_role_assignment" => IacResourceType::AzureRoleAssignment,
        "azurerm_virtual_machine" | "azurerm_linux_virtual_machine" | "azurerm_windows_virtual_machine" => IacResourceType::AzureVirtualMachine,
        "azurerm_network_security_group" => IacResourceType::AzureNetworkSecurityGroup,
        "azurerm_sql_server" | "azurerm_mssql_server" => IacResourceType::AzureSqlServer,
        "azurerm_sql_database" | "azurerm_mssql_database" => IacResourceType::AzureSqlDatabase,
        "azurerm_key_vault" => IacResourceType::AzureKeyVault,
        "azurerm_app_service" | "azurerm_linux_web_app" | "azurerm_windows_web_app" => IacResourceType::AzureAppService,
        "azurerm_function_app" | "azurerm_linux_function_app" | "azurerm_windows_function_app" => IacResourceType::AzureFunctionApp,
        "azurerm_cosmosdb_account" => IacResourceType::AzureCosmosDb,
        "azurerm_kubernetes_cluster" => IacResourceType::AzureAks,
        "azurerm_container_registry" => IacResourceType::AzureContainerRegistry,

        // GCP
        "google_storage_bucket" => IacResourceType::GcpStorageBucket,
        "google_project_iam_binding" => IacResourceType::GcpIamBinding,
        "google_project_iam_member" => IacResourceType::GcpIamMember,
        "google_compute_instance" => IacResourceType::GcpComputeInstance,
        "google_compute_firewall" => IacResourceType::GcpFirewallRule,
        "google_sql_database_instance" => IacResourceType::GcpCloudSql,
        "google_kms_crypto_key" => IacResourceType::GcpKmsKey,
        "google_cloudfunctions_function" | "google_cloudfunctions2_function" => IacResourceType::GcpCloudFunction,
        "google_container_cluster" => IacResourceType::GcpGke,
        "google_bigquery_dataset" | "google_bigquery_table" => IacResourceType::GcpBigQuery,
        "google_pubsub_topic" => IacResourceType::GcpPubSub,
        "google_secret_manager_secret" => IacResourceType::GcpSecretManager,

        // Other
        _ => IacResourceType::Other(resource_type.to_string()),
    }
}

/// Detect provider from Terraform resource type prefix
fn detect_provider_from_resource_type(resource_type: &str) -> IacCloudProvider {
    if resource_type.starts_with("aws_") {
        IacCloudProvider::Aws
    } else if resource_type.starts_with("azurerm_") {
        IacCloudProvider::Azure
    } else if resource_type.starts_with("google_") {
        IacCloudProvider::Gcp
    } else {
        IacCloudProvider::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_terraform() {
        assert!(TerraformScanner::is_terraform("", "main.tf"));
        assert!(TerraformScanner::is_terraform("", "variables.tf.json"));

        let content = r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"#;
        assert!(TerraformScanner::is_terraform(content, "unknown.txt"));
    }

    #[test]
    fn test_detect_provider() {
        let aws_content = r#"
provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "example" {}
"#;
        assert_eq!(TerraformScanner::detect_provider(aws_content), IacCloudProvider::Aws);

        let azure_content = r#"
provider "azurerm" {
  features {}
}
resource "azurerm_resource_group" "example" {}
"#;
        assert_eq!(TerraformScanner::detect_provider(azure_content), IacCloudProvider::Azure);

        let multi_content = r#"
resource "aws_s3_bucket" "example" {}
resource "google_storage_bucket" "example" {}
"#;
        assert_eq!(TerraformScanner::detect_provider(multi_content), IacCloudProvider::Multi);
    }

    #[test]
    fn test_parse_resources() {
        let scanner = TerraformScanner::new();

        let content = r#"
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "private"
}

resource "aws_instance" "web" {
  ami           = "ami-12345"
  instance_type = "t2.micro"
}
"#;

        let resources = scanner.parse_resources(content, "file-1");
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].resource_name, "example");
        assert_eq!(resources[1].resource_name, "web");
    }

    #[test]
    fn test_scan_detects_issues() {
        let scanner = TerraformScanner::new();

        let content = r#"
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;

        let findings = scanner.scan(content, "main.tf", "scan-1", "file-1");
        assert!(!findings.is_empty(), "Should detect security issues");

        // Should find public S3 bucket
        let s3_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::PublicStorage)
            .collect();
        assert!(!s3_findings.is_empty(), "Should detect public S3 bucket");

        // Should find wide open security group
        let sg_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::NetworkExposure)
            .collect();
        assert!(!sg_findings.is_empty(), "Should detect wide open security group");
    }
}
