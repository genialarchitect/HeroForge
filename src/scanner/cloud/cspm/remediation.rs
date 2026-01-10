//! Cloud remediation automation
//!
//! Generates remediation scripts and applies fixes for cloud misconfigurations

use super::*;
use anyhow::{anyhow, Result};

/// Cloud provider configuration for SDK execution
#[derive(Debug, Clone)]
pub struct CloudProviderConfig {
    /// AWS region for API calls
    pub aws_region: Option<String>,
    /// Azure subscription ID
    pub azure_subscription_id: Option<String>,
    /// Azure resource group for operations
    pub azure_resource_group: Option<String>,
    /// GCP project ID
    pub gcp_project_id: Option<String>,
}

impl Default for CloudProviderConfig {
    fn default() -> Self {
        Self {
            aws_region: std::env::var("AWS_REGION").ok().or_else(|| Some("us-east-1".to_string())),
            azure_subscription_id: std::env::var("AZURE_SUBSCRIPTION_ID").ok(),
            azure_resource_group: std::env::var("AZURE_RESOURCE_GROUP").ok(),
            gcp_project_id: std::env::var("GCP_PROJECT_ID").ok(),
        }
    }
}

/// Remediation action types
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RemediationType {
    Terraform,
    CloudFormation,
    AzureRM,
    GCloud,
    AwsCli,
    AzureCli,
    Manual,
}

/// Remediation script with approval workflow
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationScript {
    pub finding_type: String,
    pub remediation_type: RemediationType,
    pub script: String,
    pub description: String,
    pub risk_level: String,
    pub requires_approval: bool,
    pub rollback_script: Option<String>,
}

/// Remediation result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemediationResult {
    pub finding_id: String,
    pub success: bool,
    pub message: String,
    pub applied_at: chrono::DateTime<chrono::Utc>,
}

/// Cloud remediation engine
pub struct RemediationEngine {
    approval_required: bool,
    dry_run: bool,
    cloud_config: CloudProviderConfig,
}

impl RemediationEngine {
    pub fn new() -> Self {
        Self {
            approval_required: true,
            dry_run: true,
            cloud_config: CloudProviderConfig::default(),
        }
    }

    pub fn with_approval(mut self, required: bool) -> Self {
        self.approval_required = required;
        self
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_cloud_config(mut self, config: CloudProviderConfig) -> Self {
        self.cloud_config = config;
        self
    }

    /// Generate remediation scripts for findings
    pub fn generate_remediation(&self, findings: &[CspmFinding]) -> Vec<RemediationScript> {
        let mut scripts = Vec::new();

        for finding in findings {
            if let Some(script) = self.generate_script_for_finding(finding) {
                scripts.push(script);
            }
        }

        scripts
    }

    /// Generate Terraform remediation for findings
    pub fn generate_terraform_remediation(&self, findings: &[CspmFinding]) -> String {
        let mut terraform = String::new();

        terraform.push_str("# Auto-generated Terraform remediation\n");
        terraform.push_str("# Review carefully before applying\n\n");

        for finding in findings {
            if let Some(tf) = self.generate_terraform_for_finding(finding) {
                terraform.push_str(&format!("# Remediation for: {}\n", finding.finding_type));
                terraform.push_str(&format!("# Resource: {}\n", finding.resource_id));
                terraform.push_str(&tf);
                terraform.push_str("\n\n");
            }
        }

        terraform
    }

    /// Generate CloudFormation remediation for findings
    pub fn generate_cloudformation_remediation(&self, findings: &[CspmFinding]) -> String {
        let mut cfn = String::new();

        cfn.push_str("AWSTemplateFormatVersion: '2010-09-09'\n");
        cfn.push_str("Description: Auto-generated security remediation\n\n");
        cfn.push_str("Resources:\n");

        for finding in findings {
            if let Some(resource) = self.generate_cfn_for_finding(finding) {
                cfn.push_str(&format!("  # Remediation for: {}\n", finding.finding_type));
                cfn.push_str(&resource);
                cfn.push_str("\n");
            }
        }

        cfn
    }

    /// Apply remediation with approval workflow
    pub async fn apply_remediation(
        &self,
        finding: &CspmFinding,
        approved: bool,
    ) -> Result<RemediationResult> {
        if self.approval_required && !approved {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "Remediation requires approval".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        if self.dry_run {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "Dry run - no changes applied".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        // Apply the remediation
        let result = self.execute_remediation(finding).await?;

        Ok(result)
    }

    fn generate_script_for_finding(&self, finding: &CspmFinding) -> Option<RemediationScript> {
        let remediation = match finding.finding_type.as_str() {
            // AWS remediations
            "SECURITY_GROUP_OPEN_TO_WORLD" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::AwsCli,
                script: format!(
                    r#"aws ec2 revoke-security-group-ingress \
  --group-id {} \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0"#,
                    finding.resource_id
                ),
                description: "Remove SSH access from 0.0.0.0/0".to_string(),
                risk_level: "Medium".to_string(),
                requires_approval: true,
                rollback_script: Some(format!(
                    r#"aws ec2 authorize-security-group-ingress \
  --group-id {} \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0"#,
                    finding.resource_id
                )),
            },

            "S3_BUCKET_PUBLIC" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::AwsCli,
                script: format!(
                    r#"aws s3api put-public-access-block \
  --bucket {} \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true""#,
                    finding.resource_id
                ),
                description: "Block all public access to S3 bucket".to_string(),
                risk_level: "Low".to_string(),
                requires_approval: true,
                rollback_script: None,
            },

            "S3_BUCKET_NOT_ENCRYPTED" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::AwsCli,
                script: format!(
                    r#"aws s3api put-bucket-encryption \
  --bucket {} \
  --server-side-encryption-configuration \
  '{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}'"#,
                    finding.resource_id
                ),
                description: "Enable default S3 bucket encryption".to_string(),
                risk_level: "Low".to_string(),
                requires_approval: false,
                rollback_script: None,
            },

            "MFA_NOT_ENABLED" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::Manual,
                script: "Manual action required: Enable MFA for IAM user via console".to_string(),
                description: "Enable MFA for IAM user".to_string(),
                risk_level: "Low".to_string(),
                requires_approval: false,
                rollback_script: None,
            },

            "IMDSV1_ENABLED" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::AwsCli,
                script: format!(
                    r#"aws ec2 modify-instance-metadata-options \
  --instance-id {} \
  --http-tokens required \
  --http-endpoint enabled"#,
                    finding.resource_id
                ),
                description: "Enforce IMDSv2 for EC2 instance".to_string(),
                risk_level: "Medium".to_string(),
                requires_approval: true,
                rollback_script: Some(format!(
                    r#"aws ec2 modify-instance-metadata-options \
  --instance-id {} \
  --http-tokens optional"#,
                    finding.resource_id
                )),
            },

            // Azure remediations
            "STORAGE_PUBLIC_ACCESS_ENABLED" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::AzureCli,
                script: format!(
                    r#"az storage account update \
  --name {} \
  --allow-blob-public-access false"#,
                    finding.resource_id
                ),
                description: "Disable public blob access".to_string(),
                risk_level: "Low".to_string(),
                requires_approval: true,
                rollback_script: None,
            },

            "AAD_LEGACY_AUTH_ALLOWED" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::Manual,
                script: "Create Conditional Access policy to block legacy authentication".to_string(),
                description: "Block legacy authentication protocols".to_string(),
                risk_level: "Medium".to_string(),
                requires_approval: true,
                rollback_script: None,
            },

            // GCP remediations
            "GCS_BUCKET_PUBLIC" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::GCloud,
                script: format!(
                    r#"gcloud storage buckets update gs://{} \
  --no-public-access-prevention"#,
                    finding.resource_id
                ),
                description: "Remove public access from bucket".to_string(),
                risk_level: "Low".to_string(),
                requires_approval: true,
                rollback_script: None,
            },

            "FIREWALL_SSH_OPEN_TO_INTERNET" => RemediationScript {
                finding_type: finding.finding_type.clone(),
                remediation_type: RemediationType::GCloud,
                script: format!(
                    r#"gcloud compute firewall-rules update {} \
  --source-ranges="10.0.0.0/8""#,
                    finding.resource_id
                ),
                description: "Restrict SSH to internal networks".to_string(),
                risk_level: "High".to_string(),
                requires_approval: true,
                rollback_script: Some(format!(
                    r#"gcloud compute firewall-rules update {} \
  --source-ranges="0.0.0.0/0""#,
                    finding.resource_id
                )),
            },

            _ => return None,
        };

        Some(remediation)
    }

    fn generate_terraform_for_finding(&self, finding: &CspmFinding) -> Option<String> {
        let tf = match finding.finding_type.as_str() {
            "S3_BUCKET_NOT_ENCRYPTED" => format!(
                r#"resource "aws_s3_bucket_server_side_encryption_configuration" "{}_encryption" {{
  bucket = "{}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}"#,
                finding.resource_id.replace("-", "_"),
                finding.resource_id
            ),

            "S3_BUCKET_PUBLIC" => format!(
                r#"resource "aws_s3_bucket_public_access_block" "{}_public_access" {{
  bucket = "{}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"#,
                finding.resource_id.replace("-", "_"),
                finding.resource_id
            ),

            "RDS_NOT_ENCRYPTED" => format!(
                r#"# Note: Encryption cannot be enabled on existing RDS instances
# Create encrypted snapshot and restore to new encrypted instance
resource "aws_db_instance" "{}_encrypted" {{
  # ... copy existing configuration ...
  storage_encrypted = true
  kms_key_id       = aws_kms_key.rds.arn
}}"#,
                finding.resource_id.replace("-", "_")
            ),

            _ => return None,
        };

        Some(tf)
    }

    fn generate_cfn_for_finding(&self, finding: &CspmFinding) -> Option<String> {
        let cfn = match finding.finding_type.as_str() {
            "S3_BUCKET_NOT_ENCRYPTED" => format!(
                r#"  {}Encryption:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {}
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256"#,
                finding.resource_id.replace("-", ""),
                finding.resource_id
            ),

            _ => return None,
        };

        Some(cfn)
    }

    async fn execute_remediation(&self, finding: &CspmFinding) -> Result<RemediationResult> {
        log::info!(
            "Applying remediation for {} on {}",
            finding.finding_type,
            finding.resource_id
        );

        // Route to appropriate cloud provider
        let result = match finding.resource_type.as_str() {
            rt if rt.starts_with("AWS::") || rt.starts_with("aws_") => {
                self.execute_aws_remediation(finding).await
            }
            rt if rt.contains("Microsoft.") || rt.starts_with("azure_") => {
                self.execute_azure_remediation(finding).await
            }
            rt if rt.contains("gcp.") || rt.starts_with("google_") => {
                self.execute_gcp_remediation(finding).await
            }
            _ => {
                // Fall back to CLI execution
                self.execute_cli_remediation(finding).await
            }
        };

        result
    }

    /// Execute AWS SDK remediation
    async fn execute_aws_remediation(&self, finding: &CspmFinding) -> Result<RemediationResult> {
        use aws_config::BehaviorVersion;

        let region = self.cloud_config.aws_region.clone()
            .unwrap_or_else(|| "us-east-1".to_string());

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;

        match finding.finding_type.as_str() {
            "SECURITY_GROUP_OPEN_TO_WORLD" => {
                self.remediate_aws_security_group(&config, finding).await
            }
            "S3_BUCKET_PUBLIC" => {
                self.remediate_aws_s3_public_access(&config, finding).await
            }
            "S3_BUCKET_NOT_ENCRYPTED" => {
                self.remediate_aws_s3_encryption(&config, finding).await
            }
            "IMDSV1_ENABLED" => {
                self.remediate_aws_imdsv2(&config, finding).await
            }
            "RDS_NOT_ENCRYPTED" => {
                // RDS encryption can't be enabled on existing instances
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: false,
                    message: "RDS encryption requires creating a new instance from encrypted snapshot. Manual intervention required.".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            "RDS_PUBLIC_ACCESS" => {
                self.remediate_aws_rds_public_access(&config, finding).await
            }
            "IAM_POLICY_TOO_PERMISSIVE" => {
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: false,
                    message: "IAM policy remediation requires manual review of required permissions.".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            _ => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("No automated remediation available for {}", finding.finding_type),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate AWS security group open to world
    async fn remediate_aws_security_group(
        &self,
        config: &aws_config::SdkConfig,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let ec2_client = aws_sdk_ec2::Client::new(config);

        // Parse security group ID and rule details from finding
        let sg_id = &finding.resource_id;

        // Revoke SSH (port 22) from 0.0.0.0/0
        let result = ec2_client
            .revoke_security_group_ingress()
            .group_id(sg_id)
            .ip_permissions(
                aws_sdk_ec2::types::IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(22)
                    .to_port(22)
                    .ip_ranges(
                        aws_sdk_ec2::types::IpRange::builder()
                            .cidr_ip("0.0.0.0/0")
                            .build()
                    )
                    .build()
            )
            .send()
            .await;

        match result {
            Ok(_) => {
                log::info!("Successfully revoked SSH from 0.0.0.0/0 for {}", sg_id);

                // Also try to revoke RDP (port 3389)
                let _ = ec2_client
                    .revoke_security_group_ingress()
                    .group_id(sg_id)
                    .ip_permissions(
                        aws_sdk_ec2::types::IpPermission::builder()
                            .ip_protocol("tcp")
                            .from_port(3389)
                            .to_port(3389)
                            .ip_ranges(
                                aws_sdk_ec2::types::IpRange::builder()
                                    .cidr_ip("0.0.0.0/0")
                                    .build()
                            )
                            .build()
                    )
                    .send()
                    .await;

                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Revoked open SSH/RDP access from 0.0.0.0/0".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to revoke security group ingress: {}", e),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate S3 bucket public access
    async fn remediate_aws_s3_public_access(
        &self,
        config: &aws_config::SdkConfig,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let s3_client = aws_sdk_s3::Client::new(config);
        let bucket_name = &finding.resource_id;

        let result = s3_client
            .put_public_access_block()
            .bucket(bucket_name)
            .public_access_block_configuration(
                aws_sdk_s3::types::PublicAccessBlockConfiguration::builder()
                    .block_public_acls(true)
                    .ignore_public_acls(true)
                    .block_public_policy(true)
                    .restrict_public_buckets(true)
                    .build()
            )
            .send()
            .await;

        match result {
            Ok(_) => {
                log::info!("Successfully enabled public access block for bucket {}", bucket_name);
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Enabled public access block for S3 bucket".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to enable public access block: {}", e),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate S3 bucket encryption
    async fn remediate_aws_s3_encryption(
        &self,
        config: &aws_config::SdkConfig,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let s3_client = aws_sdk_s3::Client::new(config);
        let bucket_name = &finding.resource_id;

        // Build the encryption configuration
        let encryption_default = aws_sdk_s3::types::ServerSideEncryptionByDefault::builder()
            .sse_algorithm(aws_sdk_s3::types::ServerSideEncryption::Aes256)
            .build()
            .map_err(|e| anyhow!("Failed to build encryption default: {}", e))?;

        let encryption_rule = aws_sdk_s3::types::ServerSideEncryptionRule::builder()
            .apply_server_side_encryption_by_default(encryption_default)
            .build();

        let encryption_config = aws_sdk_s3::types::ServerSideEncryptionConfiguration::builder()
            .rules(encryption_rule)
            .build()
            .map_err(|e| anyhow!("Failed to build encryption config: {}", e))?;

        let result = s3_client
            .put_bucket_encryption()
            .bucket(bucket_name)
            .server_side_encryption_configuration(encryption_config)
            .send()
            .await;

        match result {
            Ok(_) => {
                log::info!("Successfully enabled default encryption for bucket {}", bucket_name);
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Enabled AES-256 default encryption for S3 bucket".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to enable bucket encryption: {}", e),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate EC2 IMDSv2 enforcement
    async fn remediate_aws_imdsv2(
        &self,
        config: &aws_config::SdkConfig,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let ec2_client = aws_sdk_ec2::Client::new(config);
        let instance_id = &finding.resource_id;

        let result = ec2_client
            .modify_instance_metadata_options()
            .instance_id(instance_id)
            .http_tokens(aws_sdk_ec2::types::HttpTokensState::Required)
            .http_endpoint(aws_sdk_ec2::types::InstanceMetadataEndpointState::Enabled)
            .send()
            .await;

        match result {
            Ok(_) => {
                log::info!("Successfully enforced IMDSv2 for instance {}", instance_id);
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Enforced IMDSv2 (http-tokens=required) for EC2 instance".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to enforce IMDSv2: {}", e),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate RDS public access
    async fn remediate_aws_rds_public_access(
        &self,
        config: &aws_config::SdkConfig,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let rds_client = aws_sdk_rds::Client::new(config);
        let db_instance_id = &finding.resource_id;

        let result = rds_client
            .modify_db_instance()
            .db_instance_identifier(db_instance_id)
            .publicly_accessible(false)
            .apply_immediately(true)
            .send()
            .await;

        match result {
            Ok(_) => {
                log::info!("Successfully disabled public access for RDS instance {}", db_instance_id);
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Disabled public accessibility for RDS instance".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            Err(e) => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to disable RDS public access: {}", e),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Execute Azure SDK remediation
    async fn execute_azure_remediation(&self, finding: &CspmFinding) -> Result<RemediationResult> {
        let subscription_id = self.cloud_config.azure_subscription_id.as_ref()
            .ok_or_else(|| anyhow!("Azure subscription ID not configured"))?;
        let resource_group = self.cloud_config.azure_resource_group.as_ref()
            .ok_or_else(|| anyhow!("Azure resource group not configured"))?;

        match finding.finding_type.as_str() {
            "STORAGE_PUBLIC_ACCESS_ENABLED" => {
                self.remediate_azure_storage_public_access(
                    subscription_id,
                    resource_group,
                    finding,
                ).await
            }
            "NSG_OPEN_TO_WORLD" => {
                self.remediate_azure_nsg(subscription_id, resource_group, finding).await
            }
            "AAD_LEGACY_AUTH_ALLOWED" => {
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: false,
                    message: "Blocking legacy auth requires Azure AD Conditional Access policy. Create via Azure Portal.".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            _ => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("No automated Azure remediation for {}", finding.finding_type),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate Azure storage account public access
    async fn remediate_azure_storage_public_access(
        &self,
        subscription_id: &str,
        resource_group: &str,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let storage_account_name = &finding.resource_id;
        let token = self.get_azure_access_token().await?;

        // Use Azure REST API to update storage account
        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}?api-version=2023-01-01",
            subscription_id, resource_group, storage_account_name
        );

        let client = reqwest::Client::new();
        let response = client
            .patch(&url)
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "properties": {
                    "allowBlobPublicAccess": false,
                    "publicNetworkAccess": "Enabled",
                    "networkAcls": {
                        "defaultAction": "Deny",
                        "bypass": "AzureServices"
                    }
                }
            }))
            .send()
            .await
            .map_err(|e| anyhow!("Azure API request failed: {}", e))?;

        if response.status().is_success() {
            log::info!("Successfully disabled public access for storage account {}", storage_account_name);
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "Disabled public blob access and set default network action to deny".to_string(),
                applied_at: chrono::Utc::now(),
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Azure API error: {}", error_text),
                applied_at: chrono::Utc::now(),
            })
        }
    }

    /// Remediate Azure NSG open to world
    async fn remediate_azure_nsg(
        &self,
        subscription_id: &str,
        resource_group: &str,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let nsg_name = &finding.resource_id;
        let token = self.get_azure_access_token().await?;

        // Get current NSG rules
        let get_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/networkSecurityGroups/{}?api-version=2023-09-01",
            subscription_id, resource_group, nsg_name
        );

        let client = reqwest::Client::new();
        let response = client
            .get(&get_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow!("Azure API request failed: {}", e))?;

        if !response.status().is_success() {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "Failed to retrieve NSG configuration".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        let nsg_config: serde_json::Value = response.json().await
            .map_err(|e| anyhow!("Failed to parse NSG config: {}", e))?;

        // Find and remove rules with source 0.0.0.0/0 or * for SSH/RDP
        let mut modified = false;
        let mut updated_rules: Vec<serde_json::Value> = Vec::new();

        if let Some(rules) = nsg_config["properties"]["securityRules"].as_array() {
            for rule in rules {
                let source = rule["properties"]["sourceAddressPrefix"].as_str().unwrap_or("");
                let dest_port = rule["properties"]["destinationPortRange"].as_str().unwrap_or("");
                let access = rule["properties"]["access"].as_str().unwrap_or("");
                let direction = rule["properties"]["direction"].as_str().unwrap_or("");

                // Skip rules that allow SSH/RDP from internet
                if (source == "*" || source == "0.0.0.0/0" || source == "Internet")
                    && access == "Allow"
                    && direction == "Inbound"
                    && (dest_port == "22" || dest_port == "3389" || dest_port == "*") {
                    modified = true;
                    log::info!("Removing insecure rule: {:?}", rule["name"]);
                    continue;
                }
                updated_rules.push(rule.clone());
            }
        }

        if !modified {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "No insecure rules found to remove".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        // Update NSG with filtered rules
        let mut updated_config = nsg_config.clone();
        updated_config["properties"]["securityRules"] = serde_json::json!(updated_rules);

        let update_response = client
            .put(&get_url)
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .json(&updated_config)
            .send()
            .await
            .map_err(|e| anyhow!("Azure API update failed: {}", e))?;

        if update_response.status().is_success() {
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "Removed insecure NSG rules allowing SSH/RDP from internet".to_string(),
                applied_at: chrono::Utc::now(),
            })
        } else {
            let error_text = update_response.text().await.unwrap_or_default();
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to update NSG: {}", error_text),
                applied_at: chrono::Utc::now(),
            })
        }
    }

    /// Execute GCP SDK remediation
    async fn execute_gcp_remediation(&self, finding: &CspmFinding) -> Result<RemediationResult> {
        let project_id = self.cloud_config.gcp_project_id.as_ref()
            .ok_or_else(|| anyhow!("GCP project ID not configured"))?;

        match finding.finding_type.as_str() {
            "GCS_BUCKET_PUBLIC" => {
                self.remediate_gcp_bucket_public_access(project_id, finding).await
            }
            "FIREWALL_SSH_OPEN_TO_INTERNET" => {
                self.remediate_gcp_firewall_rule(project_id, finding).await
            }
            "COMPUTE_DEFAULT_SERVICE_ACCOUNT" => {
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: false,
                    message: "Changing service account requires creating new VM. Consider recreating the instance with a custom service account.".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
            _ => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("No automated GCP remediation for {}", finding.finding_type),
                applied_at: chrono::Utc::now(),
            }),
        }
    }

    /// Remediate GCP bucket public access
    async fn remediate_gcp_bucket_public_access(
        &self,
        project_id: &str,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        // Use GCP REST API with Application Default Credentials
        let bucket_name = &finding.resource_id;

        // Get access token from metadata server or ADC
        let token = self.get_gcp_access_token().await?;

        let client = reqwest::Client::new();

        // Remove allUsers and allAuthenticatedUsers from IAM bindings
        let iam_url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/iam",
            bucket_name
        );

        let iam_response = client
            .get(&iam_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow!("GCP IAM request failed: {}", e))?;

        if !iam_response.status().is_success() {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "Failed to retrieve bucket IAM policy".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        let mut iam_policy: serde_json::Value = iam_response.json().await
            .map_err(|e| anyhow!("Failed to parse IAM policy: {}", e))?;

        // Filter out public bindings
        let mut modified = false;
        if let Some(bindings) = iam_policy["bindings"].as_array_mut() {
            for binding in bindings.iter_mut() {
                if let Some(members) = binding["members"].as_array() {
                    let filtered: Vec<&serde_json::Value> = members.iter()
                        .filter(|m| {
                            let member = m.as_str().unwrap_or("");
                            if member == "allUsers" || member == "allAuthenticatedUsers" {
                                modified = true;
                                false
                            } else {
                                true
                            }
                        })
                        .collect();
                    binding["members"] = serde_json::json!(filtered);
                }
            }
        }

        if !modified {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "No public access bindings found to remove".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        // Update IAM policy
        let update_response = client
            .put(&iam_url)
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .json(&iam_policy)
            .send()
            .await
            .map_err(|e| anyhow!("GCP IAM update failed: {}", e))?;

        if update_response.status().is_success() {
            log::info!("Successfully removed public access from bucket {}", bucket_name);
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: true,
                message: "Removed allUsers and allAuthenticatedUsers from bucket IAM policy".to_string(),
                applied_at: chrono::Utc::now(),
            })
        } else {
            let error_text = update_response.text().await.unwrap_or_default();
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: format!("Failed to update bucket IAM: {}", error_text),
                applied_at: chrono::Utc::now(),
            })
        }
    }

    /// Remediate GCP firewall rule allowing SSH from internet
    async fn remediate_gcp_firewall_rule(
        &self,
        project_id: &str,
        finding: &CspmFinding,
    ) -> Result<RemediationResult> {
        let token = self.get_gcp_access_token().await?;
        let firewall_rule_name = &finding.resource_id;

        let client = reqwest::Client::new();

        // Get current firewall rule
        let get_url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
            project_id, firewall_rule_name
        );

        let response = client
            .get(&get_url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| anyhow!("GCP firewall request failed: {}", e))?;

        if !response.status().is_success() {
            return Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "Failed to retrieve firewall rule".to_string(),
                applied_at: chrono::Utc::now(),
            });
        }

        let mut firewall_rule: serde_json::Value = response.json().await
            .map_err(|e| anyhow!("Failed to parse firewall rule: {}", e))?;

        // Replace 0.0.0.0/0 with internal ranges only
        if let Some(source_ranges) = firewall_rule["sourceRanges"].as_array() {
            let has_public = source_ranges.iter().any(|r| {
                let range = r.as_str().unwrap_or("");
                range == "0.0.0.0/0" || range == "::/0"
            });

            if has_public {
                // Replace with RFC1918 private ranges
                firewall_rule["sourceRanges"] = serde_json::json!([
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16"
                ]);

                // Update the firewall rule
                let update_url = format!(
                    "https://compute.googleapis.com/compute/v1/projects/{}/global/firewalls/{}",
                    project_id, firewall_rule_name
                );

                let update_response = client
                    .put(&update_url)
                    .bearer_auth(&token)
                    .header("Content-Type", "application/json")
                    .json(&firewall_rule)
                    .send()
                    .await
                    .map_err(|e| anyhow!("GCP firewall update failed: {}", e))?;

                if update_response.status().is_success() {
                    log::info!("Successfully restricted firewall rule {}", firewall_rule_name);
                    Ok(RemediationResult {
                        finding_id: finding.resource_id.clone(),
                        success: true,
                        message: "Restricted firewall rule to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)".to_string(),
                        applied_at: chrono::Utc::now(),
                    })
                } else {
                    let error_text = update_response.text().await.unwrap_or_default();
                    Ok(RemediationResult {
                        finding_id: finding.resource_id.clone(),
                        success: false,
                        message: format!("Failed to update firewall rule: {}", error_text),
                        applied_at: chrono::Utc::now(),
                    })
                }
            } else {
                Ok(RemediationResult {
                    finding_id: finding.resource_id.clone(),
                    success: true,
                    message: "Firewall rule does not have public source ranges".to_string(),
                    applied_at: chrono::Utc::now(),
                })
            }
        } else {
            Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "Unable to parse firewall rule source ranges".to_string(),
                applied_at: chrono::Utc::now(),
            })
        }
    }

    /// Get Azure access token using OAuth2 client credentials
    async fn get_azure_access_token(&self) -> Result<String> {
        let tenant_id = std::env::var("AZURE_TENANT_ID")
            .map_err(|_| anyhow!("AZURE_TENANT_ID not set"))?;
        let client_id = std::env::var("AZURE_CLIENT_ID")
            .map_err(|_| anyhow!("AZURE_CLIENT_ID not set"))?;
        let client_secret = std::env::var("AZURE_CLIENT_SECRET")
            .map_err(|_| anyhow!("AZURE_CLIENT_SECRET not set"))?;

        let token_url = format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant_id);

        let client = reqwest::Client::new();
        let response = client
            .post(&token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", "https://management.azure.com/.default"),
            ])
            .send()
            .await
            .map_err(|e| anyhow!("Azure token request failed: {}", e))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Azure OAuth2 error: {}", error_text));
        }

        let token_data: serde_json::Value = response.json().await
            .map_err(|e| anyhow!("Failed to parse Azure token response: {}", e))?;

        token_data["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("No access_token in Azure response"))
    }

    /// Get GCP access token from Application Default Credentials
    async fn get_gcp_access_token(&self) -> Result<String> {
        // Try metadata server first (for GCE/Cloud Run/GKE)
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

        let client = reqwest::Client::new();
        let metadata_response = client
            .get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await;

        if let Ok(response) = metadata_response {
            if response.status().is_success() {
                let token_data: serde_json::Value = response.json().await
                    .map_err(|e| anyhow!("Failed to parse token: {}", e))?;
                if let Some(token) = token_data["access_token"].as_str() {
                    return Ok(token.to_string());
                }
            }
        }

        // Fall back to gcloud CLI
        let output = tokio::process::Command::new("gcloud")
            .args(["auth", "print-access-token"])
            .output()
            .await
            .map_err(|e| anyhow!("Failed to run gcloud: {}", e))?;

        if output.status.success() {
            let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(token)
        } else {
            Err(anyhow!("Failed to get GCP access token. Ensure gcloud is configured or running on GCP."))
        }
    }

    /// Execute CLI-based remediation as fallback
    async fn execute_cli_remediation(&self, finding: &CspmFinding) -> Result<RemediationResult> {
        // Generate the remediation script
        let script = self.generate_script_for_finding(finding);

        match script {
            Some(remediation) => {
                // Determine which CLI to use
                let (command, args) = match remediation.remediation_type {
                    RemediationType::AwsCli => ("aws", remediation.script.clone()),
                    RemediationType::AzureCli => ("az", remediation.script.clone()),
                    RemediationType::GCloud => ("gcloud", remediation.script.clone()),
                    RemediationType::Manual => {
                        return Ok(RemediationResult {
                            finding_id: finding.resource_id.clone(),
                            success: false,
                            message: format!("Manual remediation required: {}", remediation.description),
                            applied_at: chrono::Utc::now(),
                        });
                    }
                    _ => {
                        return Ok(RemediationResult {
                            finding_id: finding.resource_id.clone(),
                            success: false,
                            message: "CLI remediation not available for this type".to_string(),
                            applied_at: chrono::Utc::now(),
                        });
                    }
                };

                // Parse the script into arguments
                let shell_args = vec!["sh", "-c", &args];

                let output = tokio::process::Command::new("sh")
                    .args(&["-c", &args])
                    .output()
                    .await
                    .map_err(|e| anyhow!("Failed to execute CLI command: {}", e))?;

                if output.status.success() {
                    log::info!("CLI remediation successful for {}", finding.finding_type);
                    Ok(RemediationResult {
                        finding_id: finding.resource_id.clone(),
                        success: true,
                        message: format!("CLI remediation applied: {}", remediation.description),
                        applied_at: chrono::Utc::now(),
                    })
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Ok(RemediationResult {
                        finding_id: finding.resource_id.clone(),
                        success: false,
                        message: format!("CLI remediation failed: {}", stderr),
                        applied_at: chrono::Utc::now(),
                    })
                }
            }
            None => Ok(RemediationResult {
                finding_id: finding.resource_id.clone(),
                success: false,
                message: "No remediation script available for this finding type".to_string(),
                applied_at: chrono::Utc::now(),
            }),
        }
    }
}

impl Default for RemediationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Get recommended remediation priority
pub fn prioritize_remediations(findings: &[CspmFinding]) -> Vec<&CspmFinding> {
    let mut prioritized: Vec<&CspmFinding> = findings.iter().collect();

    // Sort by severity
    prioritized.sort_by(|a, b| {
        let severity_order = |s: &str| match s {
            "Critical" => 0,
            "High" => 1,
            "Medium" => 2,
            "Low" => 3,
            _ => 4,
        };
        severity_order(&a.severity).cmp(&severity_order(&b.severity))
    });

    prioritized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_remediation() {
        let engine = RemediationEngine::new();
        let findings = vec![CspmFinding {
            resource_id: "sg-12345".to_string(),
            resource_type: "AWS::EC2::SecurityGroup".to_string(),
            finding_type: "SECURITY_GROUP_OPEN_TO_WORLD".to_string(),
            severity: "Critical".to_string(),
            description: "SSH open to world".to_string(),
            remediation: "Restrict access".to_string(),
        }];

        let scripts = engine.generate_remediation(&findings);
        assert!(!scripts.is_empty());
        assert!(scripts[0].script.contains("revoke-security-group-ingress"));
    }

    #[test]
    fn test_prioritize() {
        let findings = vec![
            CspmFinding {
                resource_id: "1".to_string(),
                resource_type: "test".to_string(),
                finding_type: "LOW".to_string(),
                severity: "Low".to_string(),
                description: "".to_string(),
                remediation: "".to_string(),
            },
            CspmFinding {
                resource_id: "2".to_string(),
                resource_type: "test".to_string(),
                finding_type: "CRITICAL".to_string(),
                severity: "Critical".to_string(),
                description: "".to_string(),
                remediation: "".to_string(),
            },
        ];

        let prioritized = prioritize_remediations(&findings);
        assert_eq!(prioritized[0].severity, "Critical");
    }
}
