#![allow(dead_code)]
//! Security rules engine for IaC scanning
//!
//! This module contains built-in security rules for Terraform, CloudFormation,
//! and Azure ARM templates. Rules check for common misconfigurations like
//! hardcoded secrets, public storage, missing encryption, etc.

use super::types::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde_json::Value;

/// A rule matcher that can check IaC content for security issues
pub trait RuleMatcher: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> IacSeverity;
    fn category(&self) -> IacFindingCategory;
    fn platforms(&self) -> &[IacPlatform];
    fn providers(&self) -> &[IacCloudProvider];
    fn remediation(&self) -> &str;
    fn documentation_url(&self) -> Option<&str>;
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping>;

    /// Check content and return findings
    fn check(&self, content: &str, filename: &str, platform: IacPlatform) -> Vec<RuleMatch>;

    /// Check parsed JSON/YAML content
    fn check_parsed(&self, _value: &Value, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        Vec::new()
    }
}

/// A match result from a rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub line_start: i32,
    pub line_end: i32,
    pub code_snippet: String,
    pub resource_type: Option<IacResourceType>,
    pub resource_name: Option<String>,
    pub message: Option<String>,
}

// Secret patterns to detect
lazy_static! {
    static ref SECRET_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("AWS Access Key", Regex::new(r#"(?i)(aws_access_key_id|access_key)\s*=\s*["']?[A-Z0-9]{20}["']?"#).unwrap()),
        ("AWS Secret Key", Regex::new(r#"(?i)(aws_secret_access_key|secret_key)\s*=\s*["']?[A-Za-z0-9/+=]{40}["']?"#).unwrap()),
        ("Generic API Key", Regex::new(r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}["']?"#).unwrap()),
        ("Generic Secret", Regex::new(r#"(?i)(secret|password|passwd|pwd)\s*[=:]\s*["'][^"']{8,}["']"#).unwrap()),
        ("Private Key", Regex::new(r#"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#).unwrap()),
        ("GitHub Token", Regex::new(r#"ghp_[A-Za-z0-9]{36}"#).unwrap()),
        ("Slack Token", Regex::new(r#"xox[baprs]-[A-Za-z0-9-]+"#).unwrap()),
        ("Azure Client Secret", Regex::new(r#"(?i)(client_secret|azure_client_secret)\s*=\s*["'][A-Za-z0-9_\-~.]{34,}["']"#).unwrap()),
        ("Google API Key", Regex::new(r#"AIza[A-Za-z0-9_\-]{35}"#).unwrap()),
        ("JWT Token", Regex::new(r#"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"#).unwrap()),
        ("Database Connection String", Regex::new(r#"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"#).unwrap()),
    ];

    // AWS S3 bucket public access patterns
    static ref S3_PUBLIC_ACL_PATTERN: Regex = Regex::new(r#"(?i)acl\s*=\s*["']?(public-read|public-read-write|authenticated-read)["']?"#).unwrap();

    // AWS Security Group wide open patterns
    static ref SG_WIDE_OPEN_CIDR: Regex = Regex::new(r#"(?i)cidr_blocks\s*=\s*\[?\s*["']?0\.0\.0\.0/0["']?\s*\]?"#).unwrap();
    static ref SG_IPV6_WIDE_OPEN: Regex = Regex::new(r#"(?i)ipv6_cidr_blocks\s*=\s*\[?\s*["']?::/0["']?\s*\]?"#).unwrap();

    // Missing encryption patterns
    static ref EBS_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)encrypted\s*=\s*false"#).unwrap();
    static ref RDS_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)storage_encrypted\s*=\s*false"#).unwrap();

    // Logging disabled patterns
    static ref S3_NO_LOGGING: Regex = Regex::new(r#"(?i)resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[^}]*\}"#).unwrap();
    static ref CLOUDTRAIL_DISABLED: Regex = Regex::new(r#"(?i)enable_logging\s*=\s*false"#).unwrap();

    // IAM wildcard patterns
    static ref IAM_WILDCARD_ACTION: Regex = Regex::new(r#"(?i)"Action"\s*:\s*\[?\s*["']\*["']\s*\]?"#).unwrap();
    static ref IAM_WILDCARD_RESOURCE: Regex = Regex::new(r#"(?i)"Resource"\s*:\s*\[?\s*["']\*["']\s*\]?"#).unwrap();

    // Azure storage public access
    static ref AZURE_BLOB_PUBLIC: Regex = Regex::new(r#"(?i)allow_blob_public_access\s*=\s*true"#).unwrap();
    static ref AZURE_CONTAINER_PUBLIC: Regex = Regex::new(r#"(?i)container_access_type\s*=\s*["']?(blob|container)["']?"#).unwrap();

    // Azure SQL firewall
    static ref AZURE_SQL_OPEN_FIREWALL: Regex = Regex::new(r#"(?i)start_ip_address\s*=\s*["']?0\.0\.0\.0["']?"#).unwrap();

    // GCP storage public
    static ref GCP_BUCKET_PUBLIC: Regex = Regex::new(r#"(?i)allUsers|allAuthenticatedUsers"#).unwrap();

    // SSH port exposed
    static ref SSH_PORT_OPEN: Regex = Regex::new(r#"(?i)(from_port|to_port)\s*=\s*22"#).unwrap();
    static ref RDP_PORT_OPEN: Regex = Regex::new(r#"(?i)(from_port|to_port)\s*=\s*3389"#).unwrap();
}

/// Hardcoded secrets detection rule
pub struct HardcodedSecretsRule;

impl RuleMatcher for HardcodedSecretsRule {
    fn id(&self) -> &str { "IAC001" }
    fn name(&self) -> &str { "Hardcoded Secrets" }
    fn description(&self) -> &str { "Detects hardcoded secrets, API keys, passwords, and other sensitive credentials in IaC files" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::HardcodedSecret }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation, IacPlatform::AzureArm] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws, IacCloudProvider::Azure, IacCloudProvider::Gcp] }
    fn remediation(&self) -> &str { "Use environment variables, secrets managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager), or encrypted parameter stores instead of hardcoding secrets" }
    fn documentation_url(&self) -> Option<&str> { Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS".to_string(), control_id: "1.1".to_string(), control_title: Some("Ensure credentials are not hardcoded".to_string()) },
            IacComplianceMapping { framework: "PCI-DSS".to_string(), control_id: "6.5.3".to_string(), control_title: Some("Insecure cryptographic storage".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (secret_type, pattern) in SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    // Mask the actual secret in the snippet
                    let masked_line = mask_secret(line);
                    matches.push(RuleMatch {
                        line_start: (line_num + 1) as i32,
                        line_end: (line_num + 1) as i32,
                        code_snippet: masked_line,
                        resource_type: None,
                        resource_name: None,
                        message: Some(format!("Detected {} in code", secret_type)),
                    });
                }
            }
        }

        matches
    }
}

/// AWS S3 Public Access rule
pub struct S3PublicAccessRule;

impl RuleMatcher for S3PublicAccessRule {
    fn id(&self) -> &str { "IAC002" }
    fn name(&self) -> &str { "S3 Bucket Public Access" }
    fn description(&self) -> &str { "S3 bucket has public ACL or policy allowing public access" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::PublicStorage }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Set acl = 'private' and enable S3 Block Public Access settings. Use bucket policies with Principal restrictions" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "2.1.1".to_string(), control_title: Some("Ensure all S3 buckets employ encryption-at-rest".to_string()) },
            IacComplianceMapping { framework: "PCI-DSS".to_string(), control_id: "7.1".to_string(), control_title: Some("Limit access to system components".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if S3_PUBLIC_ACL_PATTERN.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsS3Bucket),
                    resource_name: None,
                    message: Some("S3 bucket configured with public ACL".to_string()),
                });
            }
        }

        matches
    }
}

/// Security Group Wide Open rule
pub struct SecurityGroupWideOpenRule;

impl RuleMatcher for SecurityGroupWideOpenRule {
    fn id(&self) -> &str { "IAC003" }
    fn name(&self) -> &str { "Security Group Open to World" }
    fn description(&self) -> &str { "Security group allows inbound traffic from 0.0.0.0/0 or ::/0" }
    fn severity(&self) -> IacSeverity { IacSeverity::High }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::NetworkExposure }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Restrict CIDR blocks to specific IP ranges. Use security group references instead of CIDR blocks where possible" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "5.2".to_string(), control_title: Some("Ensure no security groups allow ingress from 0.0.0.0/0".to_string()) },
            IacComplianceMapping { framework: "NIST 800-53".to_string(), control_id: "AC-4".to_string(), control_title: Some("Information Flow Enforcement".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if SG_WIDE_OPEN_CIDR.is_match(line) || SG_IPV6_WIDE_OPEN.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsSecurityGroup),
                    resource_name: None,
                    message: Some("Security group allows traffic from anywhere".to_string()),
                });
            }
        }

        matches
    }
}

/// Missing EBS Encryption rule
pub struct EbsEncryptionRule;

impl RuleMatcher for EbsEncryptionRule {
    fn id(&self) -> &str { "IAC004" }
    fn name(&self) -> &str { "EBS Volume Not Encrypted" }
    fn description(&self) -> &str { "EBS volume encryption is disabled" }
    fn severity(&self) -> IacSeverity { IacSeverity::High }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::MissingEncryption }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Set encrypted = true and specify a KMS key for encryption" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "2.2.1".to_string(), control_title: Some("Ensure EBS volume encryption is enabled".to_string()) },
            IacComplianceMapping { framework: "PCI-DSS".to_string(), control_id: "3.4".to_string(), control_title: Some("Render PAN unreadable".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if EBS_NO_ENCRYPTION.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsEbsVolume),
                    resource_name: None,
                    message: Some("EBS volume encryption is explicitly disabled".to_string()),
                });
            }
        }

        matches
    }
}

/// RDS Encryption rule
pub struct RdsEncryptionRule;

impl RuleMatcher for RdsEncryptionRule {
    fn id(&self) -> &str { "IAC005" }
    fn name(&self) -> &str { "RDS Storage Not Encrypted" }
    fn description(&self) -> &str { "RDS instance storage encryption is disabled" }
    fn severity(&self) -> IacSeverity { IacSeverity::High }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::MissingEncryption }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Set storage_encrypted = true and specify a KMS key" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "2.3.1".to_string(), control_title: Some("Ensure that encryption is enabled for RDS Instances".to_string()) },
            IacComplianceMapping { framework: "HIPAA".to_string(), control_id: "164.312(a)(2)(iv)".to_string(), control_title: Some("Encryption and decryption".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if RDS_NO_ENCRYPTION.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsRdsInstance),
                    resource_name: None,
                    message: Some("RDS storage encryption is explicitly disabled".to_string()),
                });
            }
        }

        matches
    }
}

/// IAM Wildcard Permissions rule
pub struct IamWildcardRule;

impl RuleMatcher for IamWildcardRule {
    fn id(&self) -> &str { "IAC006" }
    fn name(&self) -> &str { "IAM Wildcard Permissions" }
    fn description(&self) -> &str { "IAM policy uses wildcard (*) for actions or resources" }
    fn severity(&self) -> IacSeverity { IacSeverity::High }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::IamMisconfiguration }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Follow principle of least privilege. Specify exact actions and resource ARNs instead of using wildcards" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "1.16".to_string(), control_title: Some("Ensure IAM policies are attached only to groups or roles".to_string()) },
            IacComplianceMapping { framework: "NIST 800-53".to_string(), control_id: "AC-6".to_string(), control_title: Some("Least Privilege".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if IAM_WILDCARD_ACTION.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsIamPolicy),
                    resource_name: None,
                    message: Some("IAM policy uses wildcard (*) for Actions".to_string()),
                });
            }
            if IAM_WILDCARD_RESOURCE.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsIamPolicy),
                    resource_name: None,
                    message: Some("IAM policy uses wildcard (*) for Resources".to_string()),
                });
            }
        }

        matches
    }
}

/// SSH/RDP Open to World rule
pub struct SshRdpOpenRule;

impl RuleMatcher for SshRdpOpenRule {
    fn id(&self) -> &str { "IAC007" }
    fn name(&self) -> &str { "SSH/RDP Open to World" }
    fn description(&self) -> &str { "SSH (22) or RDP (3389) port is exposed to 0.0.0.0/0" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::NetworkExposure }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws, IacCloudProvider::Azure, IacCloudProvider::Gcp] }
    fn remediation(&self) -> &str { "Restrict SSH/RDP access to specific IP addresses or use a bastion host/VPN for access" }
    fn documentation_url(&self) -> Option<&str> { Some("https://aws.amazon.com/blogs/security/securely-connect-to-linux-instances-running-in-a-private-amazon-vpc/") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "5.2".to_string(), control_title: Some("Ensure no security groups allow ingress from 0.0.0.0/0 to port 22".to_string()) },
            IacComplianceMapping { framework: "PCI-DSS".to_string(), control_id: "1.2.1".to_string(), control_title: Some("Restrict inbound and outbound traffic".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Check if this line has SSH or RDP port
            let has_ssh = SSH_PORT_OPEN.is_match(line);
            let has_rdp = RDP_PORT_OPEN.is_match(line);

            if has_ssh || has_rdp {
                // Look for 0.0.0.0/0 in surrounding context (5 lines before/after)
                let start = if line_num >= 5 { line_num - 5 } else { 0 };
                let end = std::cmp::min(line_num + 5, lines.len());
                let context = &lines[start..end].join("\n");

                if SG_WIDE_OPEN_CIDR.is_match(context) || SG_IPV6_WIDE_OPEN.is_match(context) {
                    let port_type = if has_ssh { "SSH (22)" } else { "RDP (3389)" };
                    matches.push(RuleMatch {
                        line_start: (line_num + 1) as i32,
                        line_end: (line_num + 1) as i32,
                        code_snippet: line.to_string(),
                        resource_type: Some(IacResourceType::AwsSecurityGroup),
                        resource_name: None,
                        message: Some(format!("{} port exposed to the world (0.0.0.0/0)", port_type)),
                    });
                }
            }
        }

        matches
    }
}

/// Azure Storage Public Access rule
pub struct AzureStoragePublicRule;

impl RuleMatcher for AzureStoragePublicRule {
    fn id(&self) -> &str { "IAC008" }
    fn name(&self) -> &str { "Azure Storage Public Access" }
    fn description(&self) -> &str { "Azure storage account or container allows public blob access" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::PublicStorage }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::AzureArm] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Azure] }
    fn remediation(&self) -> &str { "Set allow_blob_public_access = false on storage accounts. Use private endpoints or SAS tokens for access" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS Azure".to_string(), control_id: "3.5".to_string(), control_title: Some("Ensure that 'Public access level' is set to Private for blob containers".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if AZURE_BLOB_PUBLIC.is_match(line) || AZURE_CONTAINER_PUBLIC.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AzureStorageAccount),
                    resource_name: None,
                    message: Some("Azure storage configured with public access".to_string()),
                });
            }
        }

        matches
    }
}

/// Azure SQL Firewall Open rule
pub struct AzureSqlFirewallRule;

impl RuleMatcher for AzureSqlFirewallRule {
    fn id(&self) -> &str { "IAC009" }
    fn name(&self) -> &str { "Azure SQL Firewall Wide Open" }
    fn description(&self) -> &str { "Azure SQL firewall rule allows access from all IPs (0.0.0.0)" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::NetworkExposure }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::AzureArm] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Azure] }
    fn remediation(&self) -> &str { "Restrict SQL firewall rules to specific IP addresses. Use private endpoints for internal access" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.microsoft.com/en-us/azure/azure-sql/database/firewall-configure") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS Azure".to_string(), control_id: "4.1.2".to_string(), control_title: Some("Ensure no SQL Databases allow ingress from 0.0.0.0/0".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if AZURE_SQL_OPEN_FIREWALL.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AzureSqlServer),
                    resource_name: None,
                    message: Some("Azure SQL firewall allows access from all IPs".to_string()),
                });
            }
        }

        matches
    }
}

/// GCP Storage Public Access rule
pub struct GcpStoragePublicRule;

impl RuleMatcher for GcpStoragePublicRule {
    fn id(&self) -> &str { "IAC010" }
    fn name(&self) -> &str { "GCP Storage Public Access" }
    fn description(&self) -> &str { "GCP storage bucket allows access from allUsers or allAuthenticatedUsers" }
    fn severity(&self) -> IacSeverity { IacSeverity::Critical }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::PublicStorage }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Gcp] }
    fn remediation(&self) -> &str { "Remove allUsers and allAuthenticatedUsers bindings. Use specific service accounts or user principals" }
    fn documentation_url(&self) -> Option<&str> { Some("https://cloud.google.com/storage/docs/access-control/making-data-public") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS GCP".to_string(), control_id: "5.1".to_string(), control_title: Some("Ensure that Cloud Storage bucket is not anonymously or publicly accessible".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if GCP_BUCKET_PUBLIC.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::GcpStorageBucket),
                    resource_name: None,
                    message: Some("GCP storage bucket allows public access".to_string()),
                });
            }
        }

        matches
    }
}

/// CloudTrail Logging Disabled rule
pub struct CloudTrailLoggingRule;

impl RuleMatcher for CloudTrailLoggingRule {
    fn id(&self) -> &str { "IAC011" }
    fn name(&self) -> &str { "CloudTrail Logging Disabled" }
    fn description(&self) -> &str { "AWS CloudTrail logging is explicitly disabled" }
    fn severity(&self) -> IacSeverity { IacSeverity::High }
    fn category(&self) -> IacFindingCategory { IacFindingCategory::MissingLogging }
    fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform, IacPlatform::CloudFormation] }
    fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
    fn remediation(&self) -> &str { "Enable CloudTrail logging with enable_logging = true. Configure log file validation and encryption" }
    fn documentation_url(&self) -> Option<&str> { Some("https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html") }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> {
        vec![
            IacComplianceMapping { framework: "CIS AWS".to_string(), control_id: "3.1".to_string(), control_title: Some("Ensure CloudTrail is enabled in all regions".to_string()) },
            IacComplianceMapping { framework: "SOC2".to_string(), control_id: "CC6.1".to_string(), control_title: Some("Logical and physical access controls".to_string()) },
        ]
    }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if CLOUDTRAIL_DISABLED.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: Some(IacResourceType::AwsCloudwatch),
                    resource_name: None,
                    message: Some("CloudTrail logging is disabled".to_string()),
                });
            }
        }

        matches
    }
}

/// Get all built-in rules
pub fn get_builtin_rules() -> Vec<Box<dyn RuleMatcher>> {
    vec![
        Box::new(HardcodedSecretsRule),
        Box::new(S3PublicAccessRule),
        Box::new(SecurityGroupWideOpenRule),
        Box::new(EbsEncryptionRule),
        Box::new(RdsEncryptionRule),
        Box::new(IamWildcardRule),
        Box::new(SshRdpOpenRule),
        Box::new(AzureStoragePublicRule),
        Box::new(AzureSqlFirewallRule),
        Box::new(GcpStoragePublicRule),
        Box::new(CloudTrailLoggingRule),
    ]
}

/// Convert a builtin rule to IacRule struct
pub fn rule_matcher_to_iac_rule(matcher: &dyn RuleMatcher) -> IacRule {
    IacRule {
        id: matcher.id().to_string(),
        name: matcher.name().to_string(),
        description: matcher.description().to_string(),
        severity: matcher.severity(),
        category: matcher.category(),
        platforms: matcher.platforms().to_vec(),
        providers: matcher.providers().to_vec(),
        resource_types: Vec::new(),
        pattern: String::new(),
        pattern_type: RulePatternType::Custom,
        remediation: matcher.remediation().to_string(),
        documentation_url: matcher.documentation_url().map(String::from),
        compliance_mappings: matcher.compliance_mappings().to_vec(),
        is_builtin: true,
        is_enabled: true,
        user_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Get all builtin rules as IacRule structs
pub fn get_builtin_iac_rules() -> Vec<IacRule> {
    get_builtin_rules()
        .iter()
        .map(|r| rule_matcher_to_iac_rule(r.as_ref()))
        .collect()
}

/// Mask secrets in a line for display
fn mask_secret(line: &str) -> String {
    let mut result = line.to_string();

    // Mask common secret patterns
    let mask_patterns = [
        (Regex::new(r#"(["'])[A-Za-z0-9/+=_\-]{20,}(["'])"#).unwrap(), "$1***MASKED***$2"),
        (Regex::new(r#"(?i)(password|secret|key|token)\s*=\s*["'][^"']+["']"#).unwrap(), "$1 = \"***MASKED***\""),
    ];

    for (pattern, replacement) in mask_patterns.iter() {
        result = pattern.replace_all(&result, *replacement).to_string();
    }

    result
}

/// Custom rule matcher for user-defined regex rules
pub struct CustomRegexRule {
    rule: IacRule,
    regex: Regex,
}

impl CustomRegexRule {
    pub fn new(rule: IacRule) -> Result<Self, regex::Error> {
        let regex = Regex::new(&rule.pattern)?;
        Ok(Self { rule, regex })
    }
}

impl RuleMatcher for CustomRegexRule {
    fn id(&self) -> &str { &self.rule.id }
    fn name(&self) -> &str { &self.rule.name }
    fn description(&self) -> &str { &self.rule.description }
    fn severity(&self) -> IacSeverity { self.rule.severity }
    fn category(&self) -> IacFindingCategory { self.rule.category.clone() }
    fn platforms(&self) -> &[IacPlatform] { &self.rule.platforms }
    fn providers(&self) -> &[IacCloudProvider] { &self.rule.providers }
    fn remediation(&self) -> &str { &self.rule.remediation }
    fn documentation_url(&self) -> Option<&str> { self.rule.documentation_url.as_deref() }
    fn compliance_mappings(&self) -> Vec<IacComplianceMapping> { self.rule.compliance_mappings.clone() }

    fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            if self.regex.is_match(line) {
                matches.push(RuleMatch {
                    line_start: (line_num + 1) as i32,
                    line_end: (line_num + 1) as i32,
                    code_snippet: line.to_string(),
                    resource_type: None,
                    resource_name: None,
                    message: None,
                });
            }
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardcoded_secrets_detection() {
        let rule = HardcodedSecretsRule;

        let content = r#"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
password = "mysecretpassword123"
api_key = "sk_live_abcdef123456789012345"
"#;

        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty(), "Should detect hardcoded secrets");
    }

    #[test]
    fn test_s3_public_access_detection() {
        let rule = S3PublicAccessRule;

        let content = r#"
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
"#;

        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert_eq!(matches.len(), 1, "Should detect public S3 bucket");
    }

    #[test]
    fn test_security_group_wide_open() {
        let rule = SecurityGroupWideOpenRule;

        let content = r#"
resource "aws_security_group" "wide_open" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;

        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty(), "Should detect wide open security group");
    }

    #[test]
    fn test_iam_wildcard_detection() {
        let rule = IamWildcardRule;

        let content = r#"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
"#;

        let matches = rule.check(content, "policy.json", IacPlatform::Terraform);
        assert!(matches.len() >= 2, "Should detect wildcard action and resource");
    }
}
