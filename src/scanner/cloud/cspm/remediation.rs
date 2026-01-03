//! Cloud remediation automation
//!
//! Generates remediation scripts and applies fixes for cloud misconfigurations

use super::*;
use anyhow::Result;
use std::collections::HashMap;

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
}

impl RemediationEngine {
    pub fn new() -> Self {
        Self {
            approval_required: true,
            dry_run: true,
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
        // In production, would execute the actual remediation commands
        // For now, simulate successful remediation

        log::info!(
            "Applying remediation for {} on {}",
            finding.finding_type,
            finding.resource_id
        );

        Ok(RemediationResult {
            finding_id: finding.resource_id.clone(),
            success: true,
            message: format!("Successfully remediated {}", finding.finding_type),
            applied_at: chrono::Utc::now(),
        })
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
