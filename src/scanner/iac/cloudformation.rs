#![allow(dead_code)]
//! AWS CloudFormation template analyzer
//!
//! This module parses CloudFormation templates (JSON/YAML) and analyzes them for security issues.

use super::rules::{get_builtin_rules, RuleMatcher};
use super::types::*;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;

/// CloudFormation-specific scanner
pub struct CloudFormationScanner {
    rules: Vec<Box<dyn RuleMatcher>>,
}

impl CloudFormationScanner {
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

    /// Detect if content is CloudFormation
    pub fn is_cloudformation(content: &str, filename: &str) -> bool {
        let lower_filename = filename.to_lowercase();

        // Check common CloudFormation file patterns
        if lower_filename.ends_with(".template")
            || lower_filename.ends_with(".template.json")
            || lower_filename.ends_with(".template.yaml")
            || lower_filename.ends_with(".template.yml")
            || lower_filename.contains("cloudformation")
        {
            return true;
        }

        // Try to parse as JSON first
        if let Ok(json) = serde_json::from_str::<Value>(content) {
            return is_cfn_template(&json);
        }

        // Try to parse as YAML
        if let Ok(yaml) = serde_yaml::from_str::<Value>(content) {
            return is_cfn_template(&yaml);
        }

        // Check for CloudFormation-specific strings
        content.contains("AWSTemplateFormatVersion")
            || content.contains("AWS::") && (content.contains("Resources:") || content.contains("\"Resources\""))
    }

    /// Parse CloudFormation template
    pub fn parse_template(content: &str) -> Result<Value> {
        // Try JSON first
        if let Ok(json) = serde_json::from_str::<Value>(content) {
            return Ok(json);
        }

        // Try YAML
        serde_yaml::from_str(content).context("Failed to parse CloudFormation template as JSON or YAML")
    }

    /// Parse resources from CloudFormation template
    pub fn parse_resources(&self, template: &Value, file_id: &str) -> Vec<IacResource> {
        let mut resources = Vec::new();

        if let Some(resources_obj) = template.get("Resources").and_then(|r| r.as_object()) {
            for (name, resource) in resources_obj {
                let resource_type = resource
                    .get("Type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Unknown");

                let iac_resource_type = map_cfn_resource_type(resource_type);

                let properties = resource
                    .get("Properties")
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));

                let attributes = if let Value::Object(map) = properties {
                    map.into_iter()
                        .map(|(k, v)| (k, v))
                        .collect()
                } else {
                    HashMap::new()
                };

                resources.push(IacResource {
                    id: uuid::Uuid::new_v4().to_string(),
                    file_id: file_id.to_string(),
                    resource_type: iac_resource_type,
                    resource_name: name.clone(),
                    provider: IacCloudProvider::Aws,
                    line_start: 0, // JSON/YAML doesn't preserve line numbers easily
                    line_end: 0,
                    attributes,
                });
            }
        }

        resources
    }

    /// Scan CloudFormation template for security issues
    pub fn scan(
        &self,
        content: &str,
        filename: &str,
        scan_id: &str,
        file_id: &str,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        // Run text-based rules
        for rule in &self.rules {
            if !rule.platforms().contains(&IacPlatform::CloudFormation) {
                continue;
            }

            let matches = rule.check(content, filename, IacPlatform::CloudFormation);

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

        // Run structure-based checks
        if let Ok(template) = Self::parse_template(content) {
            findings.extend(self.check_template_structure(&template, scan_id, file_id));
        }

        findings
    }

    /// Check CloudFormation template structure for issues
    fn check_template_structure(
        &self,
        template: &Value,
        scan_id: &str,
        file_id: &str,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        if let Some(resources) = template.get("Resources").and_then(|r| r.as_object()) {
            for (name, resource) in resources {
                let resource_type = resource
                    .get("Type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                // Check S3 bucket configuration
                if resource_type == "AWS::S3::Bucket" {
                    findings.extend(check_s3_bucket(resource, name, scan_id, file_id));
                }

                // Check Security Group configuration
                if resource_type == "AWS::EC2::SecurityGroup" {
                    findings.extend(check_security_group(resource, name, scan_id, file_id));
                }

                // Check RDS instance configuration
                if resource_type == "AWS::RDS::DBInstance" {
                    findings.extend(check_rds_instance(resource, name, scan_id, file_id));
                }

                // Check IAM role configuration
                if resource_type == "AWS::IAM::Role" || resource_type == "AWS::IAM::Policy" {
                    findings.extend(check_iam_policy(resource, name, scan_id, file_id));
                }

                // Check Lambda function configuration
                if resource_type == "AWS::Lambda::Function" {
                    findings.extend(check_lambda_function(resource, name, scan_id, file_id));
                }

                // Check EBS volume configuration
                if resource_type == "AWS::EC2::Volume" {
                    findings.extend(check_ebs_volume(resource, name, scan_id, file_id));
                }
            }
        }

        findings
    }

    /// Analyze a single CloudFormation file
    pub fn analyze_file(&self, content: &str, filename: &str) -> Result<AnalyzeFileResponse> {
        let file_id = uuid::Uuid::new_v4().to_string();
        let scan_id = uuid::Uuid::new_v4().to_string();

        let template = Self::parse_template(content)?;
        let resources = self.parse_resources(&template, &file_id);
        let findings = self.scan(content, filename, &scan_id, &file_id);

        let line_count = content.lines().count() as i32;

        let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
        for finding in &findings {
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;
        }

        Ok(AnalyzeFileResponse {
            platform: IacPlatform::CloudFormation,
            provider: IacCloudProvider::Aws,
            resources,
            findings,
            summary: FileSummary {
                line_count,
                resource_count: 0,
                finding_count: 0,
                findings_by_severity,
            },
        })
    }
}

impl Default for CloudFormationScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a JSON/YAML value looks like a CloudFormation template
fn is_cfn_template(value: &Value) -> bool {
    // Check for AWSTemplateFormatVersion
    if value.get("AWSTemplateFormatVersion").is_some() {
        return true;
    }

    // Check for Resources with AWS:: types
    if let Some(resources) = value.get("Resources").and_then(|r| r.as_object()) {
        for resource in resources.values() {
            if let Some(rtype) = resource.get("Type").and_then(|t| t.as_str()) {
                if rtype.starts_with("AWS::") {
                    return true;
                }
            }
        }
    }

    false
}

/// Map CloudFormation resource type to IacResourceType
fn map_cfn_resource_type(resource_type: &str) -> IacResourceType {
    match resource_type {
        "AWS::S3::Bucket" => IacResourceType::AwsS3Bucket,
        "AWS::IAM::Role" => IacResourceType::AwsIamRole,
        "AWS::IAM::Policy" | "AWS::IAM::ManagedPolicy" => IacResourceType::AwsIamPolicy,
        "AWS::IAM::User" => IacResourceType::AwsIamUser,
        "AWS::EC2::Instance" => IacResourceType::AwsEc2Instance,
        "AWS::EC2::SecurityGroup" => IacResourceType::AwsSecurityGroup,
        "AWS::RDS::DBInstance" => IacResourceType::AwsRdsInstance,
        "AWS::Lambda::Function" => IacResourceType::AwsLambdaFunction,
        "AWS::KMS::Key" => IacResourceType::AwsKmsKey,
        "AWS::EC2::Volume" => IacResourceType::AwsEbsVolume,
        "AWS::ElasticLoadBalancing::LoadBalancer" | "AWS::ElasticLoadBalancingV2::LoadBalancer" => IacResourceType::AwsElb,
        "AWS::SNS::Topic" => IacResourceType::AwsSns,
        "AWS::SQS::Queue" => IacResourceType::AwsSqs,
        "AWS::Logs::LogGroup" => IacResourceType::AwsCloudwatch,
        "AWS::EC2::VPC" => IacResourceType::AwsVpc,
        "AWS::EC2::Subnet" => IacResourceType::AwsSubnet,
        "AWS::EKS::Cluster" => IacResourceType::AwsEks,
        "AWS::ECS::Cluster" | "AWS::ECS::Service" => IacResourceType::AwsEcs,
        "AWS::ElastiCache::CacheCluster" => IacResourceType::AwsElasticache,
        "AWS::DynamoDB::Table" => IacResourceType::AwsDynamodb,
        "AWS::SecretsManager::Secret" => IacResourceType::AwsSecretsManager,
        _ => IacResourceType::Other(resource_type.to_string()),
    }
}

/// Check S3 bucket for security issues
fn check_s3_bucket(resource: &Value, name: &str, scan_id: &str, file_id: &str) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    // Check for public ACL
    if let Some(acl) = properties.get("AccessControl").and_then(|a| a.as_str()) {
        if acl == "PublicRead" || acl == "PublicReadWrite" || acl == "AuthenticatedRead" {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC002",
                IacSeverity::Critical,
                IacFindingCategory::PublicStorage,
                "S3 Bucket Public Access",
                &format!("S3 bucket '{}' has public ACL: {}", name, acl),
                Some(IacResourceType::AwsS3Bucket),
                Some(name.to_string()),
                "Set AccessControl to Private and use bucket policies with restricted principals",
            ));
        }
    }

    // Check for missing encryption
    if properties.get("BucketEncryption").is_none() {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC012",
            IacSeverity::Medium,
            IacFindingCategory::MissingEncryption,
            "S3 Bucket Missing Encryption",
            &format!("S3 bucket '{}' does not have server-side encryption configured", name),
            Some(IacResourceType::AwsS3Bucket),
            Some(name.to_string()),
            "Add BucketEncryption with ServerSideEncryptionConfiguration using SSE-S3 or SSE-KMS",
        ));
    }

    // Check for missing logging
    if properties.get("LoggingConfiguration").is_none() {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC013",
            IacSeverity::Low,
            IacFindingCategory::MissingLogging,
            "S3 Bucket Missing Access Logging",
            &format!("S3 bucket '{}' does not have access logging enabled", name),
            Some(IacResourceType::AwsS3Bucket),
            Some(name.to_string()),
            "Add LoggingConfiguration to enable access logging to a separate bucket",
        ));
    }

    // Check for missing versioning
    if let Some(versioning) = properties.get("VersioningConfiguration") {
        let status = versioning.get("Status").and_then(|s| s.as_str()).unwrap_or("");
        if status != "Enabled" {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC014",
                IacSeverity::Low,
                IacFindingCategory::BestPractice,
                "S3 Bucket Versioning Not Enabled",
                &format!("S3 bucket '{}' does not have versioning enabled", name),
                Some(IacResourceType::AwsS3Bucket),
                Some(name.to_string()),
                "Enable versioning by setting VersioningConfiguration.Status to 'Enabled'",
            ));
        }
    } else {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC014",
            IacSeverity::Low,
            IacFindingCategory::BestPractice,
            "S3 Bucket Versioning Not Enabled",
            &format!("S3 bucket '{}' does not have versioning configured", name),
            Some(IacResourceType::AwsS3Bucket),
            Some(name.to_string()),
            "Add VersioningConfiguration with Status: Enabled",
        ));
    }

    findings
}

/// Check Security Group for security issues
fn check_security_group(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    if let Some(ingress_rules) = properties.get("SecurityGroupIngress").and_then(|r| r.as_array()) {
        for rule in ingress_rules {
            // Check for wide open CIDR
            let cidr = rule.get("CidrIp").and_then(|c| c.as_str()).unwrap_or("");
            let cidr_ipv6 = rule.get("CidrIpv6").and_then(|c| c.as_str()).unwrap_or("");

            if cidr == "0.0.0.0/0" || cidr_ipv6 == "::/0" {
                let from_port = rule.get("FromPort").and_then(|p| p.as_i64()).unwrap_or(0);
                let to_port = rule.get("ToPort").and_then(|p| p.as_i64()).unwrap_or(0);

                // Check for SSH/RDP specifically
                if from_port <= 22 && to_port >= 22 {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC007",
                        IacSeverity::Critical,
                        IacFindingCategory::NetworkExposure,
                        "SSH Open to World",
                        &format!("Security group '{}' allows SSH (port 22) from anywhere", name),
                        Some(IacResourceType::AwsSecurityGroup),
                        Some(name.to_string()),
                        "Restrict SSH access to specific IP addresses or use a bastion host",
                    ));
                } else if from_port <= 3389 && to_port >= 3389 {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC007",
                        IacSeverity::Critical,
                        IacFindingCategory::NetworkExposure,
                        "RDP Open to World",
                        &format!("Security group '{}' allows RDP (port 3389) from anywhere", name),
                        Some(IacResourceType::AwsSecurityGroup),
                        Some(name.to_string()),
                        "Restrict RDP access to specific IP addresses or use a VPN",
                    ));
                } else {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC003",
                        IacSeverity::High,
                        IacFindingCategory::NetworkExposure,
                        "Security Group Open to World",
                        &format!(
                            "Security group '{}' allows traffic on ports {}-{} from anywhere",
                            name, from_port, to_port
                        ),
                        Some(IacResourceType::AwsSecurityGroup),
                        Some(name.to_string()),
                        "Restrict CIDR blocks to specific IP ranges",
                    ));
                }
            }
        }
    }

    findings
}

/// Check RDS instance for security issues
fn check_rds_instance(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    // Check for storage encryption
    let encrypted = properties
        .get("StorageEncrypted")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    if !encrypted {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC005",
            IacSeverity::High,
            IacFindingCategory::MissingEncryption,
            "RDS Storage Not Encrypted",
            &format!("RDS instance '{}' does not have storage encryption enabled", name),
            Some(IacResourceType::AwsRdsInstance),
            Some(name.to_string()),
            "Set StorageEncrypted to true and specify a KmsKeyId",
        ));
    }

    // Check for public accessibility
    let publicly_accessible = properties
        .get("PubliclyAccessible")
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    if publicly_accessible {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC015",
            IacSeverity::Critical,
            IacFindingCategory::NetworkExposure,
            "RDS Instance Publicly Accessible",
            &format!("RDS instance '{}' is configured to be publicly accessible", name),
            Some(IacResourceType::AwsRdsInstance),
            Some(name.to_string()),
            "Set PubliclyAccessible to false and use VPC security groups for access control",
        ));
    }

    // Check for deletion protection
    let deletion_protection = properties
        .get("DeletionProtection")
        .and_then(|d| d.as_bool())
        .unwrap_or(false);

    if !deletion_protection {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC016",
            IacSeverity::Low,
            IacFindingCategory::BestPractice,
            "RDS Deletion Protection Disabled",
            &format!("RDS instance '{}' does not have deletion protection enabled", name),
            Some(IacResourceType::AwsRdsInstance),
            Some(name.to_string()),
            "Set DeletionProtection to true for production databases",
        ));
    }

    findings
}

/// Check IAM policy for security issues
fn check_iam_policy(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    // Check AssumeRolePolicyDocument or PolicyDocument
    let policy_docs = [
        properties.get("AssumeRolePolicyDocument"),
        properties.get("PolicyDocument"),
    ];

    for policy_doc in policy_docs.iter().flatten() {
        if let Some(statements) = policy_doc.get("Statement").and_then(|s| s.as_array()) {
            for statement in statements {
                let effect = statement.get("Effect").and_then(|e| e.as_str()).unwrap_or("");

                if effect == "Allow" {
                    // Check for wildcard actions
                    if let Some(action) = statement.get("Action") {
                        let has_wildcard = match action {
                            Value::String(s) => s == "*",
                            Value::Array(arr) => arr.iter().any(|a| a.as_str() == Some("*")),
                            _ => false,
                        };

                        if has_wildcard {
                            findings.push(create_finding(
                                scan_id,
                                file_id,
                                "IAC006",
                                IacSeverity::High,
                                IacFindingCategory::IamMisconfiguration,
                                "IAM Wildcard Actions",
                                &format!("IAM resource '{}' uses wildcard (*) for actions", name),
                                Some(IacResourceType::AwsIamPolicy),
                                Some(name.to_string()),
                                "Specify exact actions instead of using wildcards. Follow principle of least privilege",
                            ));
                        }
                    }

                    // Check for wildcard resources
                    if let Some(resource_val) = statement.get("Resource") {
                        let has_wildcard = match resource_val {
                            Value::String(s) => s == "*",
                            Value::Array(arr) => arr.iter().any(|r| r.as_str() == Some("*")),
                            _ => false,
                        };

                        if has_wildcard {
                            findings.push(create_finding(
                                scan_id,
                                file_id,
                                "IAC006",
                                IacSeverity::High,
                                IacFindingCategory::IamMisconfiguration,
                                "IAM Wildcard Resources",
                                &format!("IAM resource '{}' uses wildcard (*) for resources", name),
                                Some(IacResourceType::AwsIamPolicy),
                                Some(name.to_string()),
                                "Specify exact resource ARNs instead of using wildcards",
                            ));
                        }
                    }
                }
            }
        }
    }

    // Check Policies array for inline policies
    if let Some(policies) = properties.get("Policies").and_then(|p| p.as_array()) {
        for policy in policies {
            if let Some(policy_doc) = policy.get("PolicyDocument") {
                let mut inline_findings = check_iam_policy(
                    &serde_json::json!({"Properties": {"PolicyDocument": policy_doc}}),
                    name,
                    scan_id,
                    file_id,
                );
                findings.append(&mut inline_findings);
            }
        }
    }

    findings
}

/// Check Lambda function for security issues
fn check_lambda_function(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    // Check for environment variable secrets
    if let Some(env_vars) = properties
        .get("Environment")
        .and_then(|e| e.get("Variables"))
        .and_then(|v| v.as_object())
    {
        for (key, _value) in env_vars {
            let key_lower = key.to_lowercase();
            if key_lower.contains("password")
                || key_lower.contains("secret")
                || key_lower.contains("api_key")
                || key_lower.contains("apikey")
            {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC017",
                    IacSeverity::High,
                    IacFindingCategory::HardcodedSecret,
                    "Lambda Environment Variable May Contain Secret",
                    &format!(
                        "Lambda function '{}' has environment variable '{}' that may contain a secret",
                        name, key
                    ),
                    Some(IacResourceType::AwsLambdaFunction),
                    Some(name.to_string()),
                    "Use AWS Secrets Manager or Parameter Store to store secrets and reference them in the function",
                ));
            }
        }
    }

    // Check for reserved concurrent executions (DoS protection)
    if properties.get("ReservedConcurrentExecutions").is_none() {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC018",
            IacSeverity::Low,
            IacFindingCategory::BestPractice,
            "Lambda Missing Concurrency Limit",
            &format!(
                "Lambda function '{}' does not have reserved concurrent executions set",
                name
            ),
            Some(IacResourceType::AwsLambdaFunction),
            Some(name.to_string()),
            "Set ReservedConcurrentExecutions to prevent runaway invocations and control costs",
        ));
    }

    findings
}

/// Check EBS volume for security issues
fn check_ebs_volume(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("Properties").unwrap_or(&Value::Null);

    // Check for encryption
    let encrypted = properties
        .get("Encrypted")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    if !encrypted {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC004",
            IacSeverity::High,
            IacFindingCategory::MissingEncryption,
            "EBS Volume Not Encrypted",
            &format!("EBS volume '{}' does not have encryption enabled", name),
            Some(IacResourceType::AwsEbsVolume),
            Some(name.to_string()),
            "Set Encrypted to true and specify a KmsKeyId for encryption",
        ));
    }

    findings
}

/// Helper to create an IacFinding
fn create_finding(
    scan_id: &str,
    file_id: &str,
    rule_id: &str,
    severity: IacSeverity,
    category: IacFindingCategory,
    title: &str,
    description: &str,
    resource_type: Option<IacResourceType>,
    resource_name: Option<String>,
    remediation: &str,
) -> IacFinding {
    IacFinding {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: scan_id.to_string(),
        file_id: file_id.to_string(),
        rule_id: rule_id.to_string(),
        severity,
        category,
        title: title.to_string(),
        description: description.to_string(),
        resource_type,
        resource_name,
        line_start: 0,
        line_end: 0,
        code_snippet: None,
        remediation: remediation.to_string(),
        documentation_url: None,
        compliance_mappings: Vec::new(),
        status: IacFindingStatus::Open,
        suppressed: false,
        suppression_reason: None,
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cloudformation() {
        // Test with AWSTemplateFormatVersion
        let cfn_content = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {}
        }"#;
        assert!(CloudFormationScanner::is_cloudformation(cfn_content, "template.json"));

        // Test YAML format
        let yaml_content = r#"
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"#;
        assert!(CloudFormationScanner::is_cloudformation(yaml_content, "template.yaml"));

        // Test filename-based detection
        assert!(CloudFormationScanner::is_cloudformation("", "my-cloudformation.template"));
    }

    #[test]
    fn test_parse_template() {
        let json_content = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket"
                }
            }
        }"#;

        let template = CloudFormationScanner::parse_template(json_content).unwrap();
        assert!(template.get("Resources").is_some());
    }

    #[test]
    fn test_scan_detects_public_s3() {
        let scanner = CloudFormationScanner::new();

        let content = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "PublicBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "AccessControl": "PublicRead"
                    }
                }
            }
        }"#;

        let findings = scanner.scan(content, "template.json", "scan-1", "file-1");
        let public_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::PublicStorage)
            .collect();

        assert!(!public_findings.is_empty(), "Should detect public S3 bucket");
    }

    #[test]
    fn test_scan_detects_security_group_issues() {
        let scanner = CloudFormationScanner::new();

        let content = r#"{
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "OpenSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Open SG",
                        "SecurityGroupIngress": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "CidrIp": "0.0.0.0/0"
                            }
                        ]
                    }
                }
            }
        }"#;

        let findings = scanner.scan(content, "template.json", "scan-1", "file-1");
        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::NetworkExposure)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect open security group");
    }
}
