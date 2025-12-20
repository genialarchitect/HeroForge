//! AWS Cloud Infrastructure Scanner
//!
//! This module provides scanning capabilities for AWS cloud resources including:
//! - IAM: Users, roles, policies, access keys
//! - Storage: S3 buckets and their permissions
//! - Compute: EC2 instances and their security configurations
//! - Network: Security groups, VPCs, network ACLs
//! - Database: RDS instances and their security settings
//!
//! **WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY.**

use super::types::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// AWS Cloud Scanner implementation
pub struct AwsScanner {
    /// Whether to use demo/mock mode (no real API calls)
    demo_mode: bool,
}

impl AwsScanner {
    /// Create a new AWS scanner
    pub fn new(demo_mode: bool) -> Self {
        Self { demo_mode }
    }

    /// Load AWS configuration and create SDK clients
    async fn load_aws_config(&self, regions: &[String]) -> Result<aws_config::SdkConfig> {
        let region = regions.first().map(|r| r.as_str()).unwrap_or("us-east-1");
        let region_provider = aws_config::Region::new(region.to_string());

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        Ok(config)
    }

    /// Scan IAM using real AWS SDK
    async fn scan_iam_real(&self, regions: &[String]) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let config = self.load_aws_config(regions).await?;
        let iam_client = aws_sdk_iam::Client::new(&config);

        // List IAM Users
        log::info!("Scanning IAM users...");
        let users_response = iam_client.list_users().send().await?;

        for user in users_response.users() {
            let user_name = user.user_name();
            let user_id = user.user_id();
            let arn = user.arn();
            let aws_dt = user.create_date();
            let create_date = DateTime::from_timestamp(aws_dt.secs(), aws_dt.subsec_nanos() as u32);

            let resource_id = Uuid::new_v4().to_string();

            // Check for MFA devices
            let mfa_response = iam_client
                .list_mfa_devices()
                .user_name(user_name)
                .send()
                .await;
            let has_mfa = mfa_response
                .map(|r| !r.mfa_devices().is_empty())
                .unwrap_or(false);

            // Check for access keys
            let access_keys = iam_client
                .list_access_keys()
                .user_name(user_name)
                .send()
                .await;

            let mut oldest_key_days = 0i32;
            if let Ok(keys_resp) = &access_keys {
                for key in keys_resp.access_key_metadata() {
                    if let Some(created) = key.create_date() {
                        let created_dt = DateTime::from_timestamp(created.secs(), created.subsec_nanos())
                            .unwrap_or_else(|| Utc::now());
                        let days = (now - created_dt).num_days() as i32;
                        if days > oldest_key_days {
                            oldest_key_days = days;
                        }
                    }
                }
            }

            // Get login profile to check console access
            let has_console_access = iam_client
                .get_login_profile()
                .user_name(user_name)
                .send()
                .await
                .is_ok();

            // Check attached policies
            let attached_policies = iam_client
                .list_attached_user_policies()
                .user_name(user_name)
                .send()
                .await;
            let policies: Vec<String> = attached_policies
                .map(|r| r.attached_policies().iter().filter_map(|p| p.policy_name().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let has_admin = policies.iter().any(|p| p.contains("AdministratorAccess") || p.contains("AdminAccess"));

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: user_id.to_string(),
                resource_type: CloudResourceType::IamUser,
                provider: CloudProvider::Aws,
                region: Some("global".to_string()),
                name: Some(user_name.to_string()),
                arn: Some(arn.to_string()),
                tags: HashMap::new(),
                metadata: serde_json::json!({
                    "has_mfa": has_mfa,
                    "access_key_age_days": oldest_key_days,
                    "has_console_access": has_console_access,
                    "attached_policies": policies,
                    "create_date": create_date.map(|d| d.to_rfc3339())
                }),
                state: Some("Active".to_string()),
                discovered_at: now,
            });

            // Check for MFA issues
            if has_console_access && !has_mfa {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: if has_admin { FindingSeverity::Critical } else { FindingSeverity::High },
                    title: "IAM User Without MFA".to_string(),
                    description: format!(
                        "IAM user '{}' has console access but MFA is not enabled. {}",
                        user_name,
                        if has_admin { "This user has administrator access, making this a critical security issue." } else { "" }
                    ),
                    remediation: Some("Enable MFA for all IAM users with console access.".to_string()),
                    compliance_mappings: vec![
                        ComplianceMapping {
                            framework: "CIS AWS".to_string(),
                            control_id: "1.10".to_string(),
                            control_title: Some("Ensure multi-factor authentication (MFA) is enabled for all IAM users".to_string()),
                        },
                    ],
                    affected_resource_arn: Some(arn.to_string()),
                    evidence: Some(FindingEvidence {
                        description: "User has console access but no MFA device configured".to_string(),
                        raw_data: Some(serde_json::json!({
                            "has_mfa": false,
                            "has_console_access": true
                        })),
                        expected: Some("MFA enabled".to_string()),
                        actual: Some("No MFA configured".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            // Check for stale access keys
            if oldest_key_days > 90 {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::BestPractice,
                    severity: FindingSeverity::High,
                    title: "Stale Access Keys".to_string(),
                    description: format!(
                        "IAM user '{}' has access keys older than 90 days ({} days). Regular key rotation reduces risk.",
                        user_name, oldest_key_days
                    ),
                    remediation: Some("Rotate access keys at least every 90 days.".to_string()),
                    compliance_mappings: vec![
                        ComplianceMapping {
                            framework: "CIS AWS".to_string(),
                            control_id: "1.14".to_string(),
                            control_title: Some("Ensure access keys are rotated every 90 days or less".to_string()),
                        },
                    ],
                    affected_resource_arn: Some(arn.to_string()),
                    evidence: Some(FindingEvidence {
                        description: "Access key age exceeds 90-day rotation policy".to_string(),
                        raw_data: Some(serde_json::json!({
                            "access_key_age_days": oldest_key_days
                        })),
                        expected: Some("< 90 days".to_string()),
                        actual: Some(format!("{} days", oldest_key_days)),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }
        }

        // List IAM Roles and check trust policies
        log::info!("Scanning IAM roles...");
        let roles_response = iam_client.list_roles().send().await?;

        for role in roles_response.roles() {
            let role_name = role.role_name();
            let role_id = role.role_id();
            let arn = role.arn();
            let assume_role_policy = role.assume_role_policy_document().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            // Parse trust policy to check for wildcards
            let decoded_policy = urlencoding::decode(assume_role_policy).unwrap_or_default();
            let has_wildcard_principal = decoded_policy.contains("\"Principal\":\"*\"") ||
                decoded_policy.contains("\"Principal\": \"*\"") ||
                decoded_policy.contains("\"AWS\":\"*\"") ||
                decoded_policy.contains("\"AWS\": \"*\"");

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: role_id.to_string(),
                resource_type: CloudResourceType::IamRole,
                provider: CloudProvider::Aws,
                region: Some("global".to_string()),
                name: Some(role_name.to_string()),
                arn: Some(arn.to_string()),
                tags: HashMap::new(),
                metadata: serde_json::json!({
                    "assume_role_policy": decoded_policy
                }),
                state: Some("Active".to_string()),
                discovered_at: now,
            });

            if has_wildcard_principal {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: FindingSeverity::Critical,
                    title: "IAM Role with Wildcard Principal in Trust Policy".to_string(),
                    description: format!(
                        "IAM role '{}' has a trust policy that allows any AWS principal to assume the role.",
                        role_name
                    ),
                    remediation: Some("Restrict the trust policy to specific AWS accounts, services, or federated identities.".to_string()),
                    compliance_mappings: vec![
                        ComplianceMapping {
                            framework: "CIS AWS".to_string(),
                            control_id: "1.16".to_string(),
                            control_title: Some("Ensure IAM policies are attached only to groups or roles".to_string()),
                        },
                    ],
                    affected_resource_arn: Some(arn.to_string()),
                    evidence: Some(FindingEvidence {
                        description: "Trust policy allows any principal to assume this role".to_string(),
                        raw_data: Some(serde_json::json!({
                            "principal": "*"
                        })),
                        expected: Some("Specific principal(s)".to_string()),
                        actual: Some("* (wildcard)".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }
        }

        Ok((resources, findings))
    }

    /// Scan S3 using real AWS SDK
    async fn scan_storage_real(&self, regions: &[String]) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let config = self.load_aws_config(regions).await?;
        let s3_client = aws_sdk_s3::Client::new(&config);

        log::info!("Scanning S3 buckets...");
        let buckets_response = s3_client.list_buckets().send().await?;

        for bucket in buckets_response.buckets() {
            let bucket_name = bucket.name().unwrap_or("unknown");
            let resource_id = Uuid::new_v4().to_string();

            // Get bucket location
            let location = s3_client
                .get_bucket_location()
                .bucket(bucket_name)
                .send()
                .await
                .ok()
                .and_then(|r| r.location_constraint().map(|l| l.to_string()))
                .unwrap_or_else(|| "us-east-1".to_string());

            // Check public access block
            let public_access = s3_client
                .get_public_access_block()
                .bucket(bucket_name)
                .send()
                .await;

            let (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) =
                if let Ok(pab) = &public_access {
                    if let Some(config) = pab.public_access_block_configuration() {
                        (
                            config.block_public_acls().unwrap_or(false),
                            config.ignore_public_acls().unwrap_or(false),
                            config.block_public_policy().unwrap_or(false),
                            config.restrict_public_buckets().unwrap_or(false),
                        )
                    } else {
                        (false, false, false, false)
                    }
                } else {
                    (false, false, false, false)
                };

            // Check encryption
            let encryption = s3_client
                .get_bucket_encryption()
                .bucket(bucket_name)
                .send()
                .await;
            let has_encryption = encryption.is_ok();

            // Check versioning
            let versioning = s3_client
                .get_bucket_versioning()
                .bucket(bucket_name)
                .send()
                .await;
            let versioning_enabled = versioning
                .ok()
                .and_then(|v| v.status().map(|s| s.as_str() == "Enabled"))
                .unwrap_or(false);

            // Check logging
            let logging = s3_client
                .get_bucket_logging()
                .bucket(bucket_name)
                .send()
                .await;
            let logging_enabled = logging
                .ok()
                .and_then(|l| l.logging_enabled().map(|_| true))
                .unwrap_or(false);

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: bucket_name.to_string(),
                resource_type: CloudResourceType::S3Bucket,
                provider: CloudProvider::Aws,
                region: Some(location.clone()),
                name: Some(bucket_name.to_string()),
                arn: Some(format!("arn:aws:s3:::{}", bucket_name)),
                tags: HashMap::new(),
                metadata: serde_json::json!({
                    "public_access_block": {
                        "block_public_acls": block_public_acls,
                        "ignore_public_acls": ignore_public_acls,
                        "block_public_policy": block_public_policy,
                        "restrict_public_buckets": restrict_public_buckets
                    },
                    "versioning": versioning_enabled,
                    "encryption": if has_encryption { "enabled" } else { "none" },
                    "logging_enabled": logging_enabled
                }),
                state: Some("Available".to_string()),
                discovered_at: now,
            });

            // Check for public access issues
            if !block_public_acls || !ignore_public_acls || !block_public_policy || !restrict_public_buckets {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Exposure,
                    severity: FindingSeverity::High,
                    title: "S3 Bucket with Public Access Block Disabled".to_string(),
                    description: format!(
                        "S3 bucket '{}' does not have all public access block settings enabled.",
                        bucket_name
                    ),
                    remediation: Some("Enable all S3 Block Public Access settings.".to_string()),
                    compliance_mappings: vec![
                        ComplianceMapping {
                            framework: "CIS AWS".to_string(),
                            control_id: "2.1.5".to_string(),
                            control_title: Some("Ensure that S3 Buckets are configured with 'Block public access'".to_string()),
                        },
                    ],
                    affected_resource_arn: Some(format!("arn:aws:s3:::{}", bucket_name)),
                    evidence: Some(FindingEvidence {
                        description: "S3 Block Public Access is not fully enabled".to_string(),
                        raw_data: Some(serde_json::json!({
                            "block_public_acls": block_public_acls,
                            "ignore_public_acls": ignore_public_acls,
                            "block_public_policy": block_public_policy,
                            "restrict_public_buckets": restrict_public_buckets
                        })),
                        expected: Some("All public access blocks enabled".to_string()),
                        actual: Some("Some public access blocks disabled".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            // Check for missing encryption
            if !has_encryption {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: FindingSeverity::Medium,
                    title: "S3 Bucket Without Default Encryption".to_string(),
                    description: format!(
                        "S3 bucket '{}' does not have default encryption enabled.",
                        bucket_name
                    ),
                    remediation: Some("Enable default encryption using SSE-S3 or SSE-KMS.".to_string()),
                    compliance_mappings: vec![
                        ComplianceMapping {
                            framework: "CIS AWS".to_string(),
                            control_id: "2.1.1".to_string(),
                            control_title: Some("Ensure all S3 buckets employ encryption-at-rest".to_string()),
                        },
                    ],
                    affected_resource_arn: Some(format!("arn:aws:s3:::{}", bucket_name)),
                    evidence: Some(FindingEvidence {
                        description: "No default encryption configured".to_string(),
                        raw_data: Some(serde_json::json!({"encryption": "none"})),
                        expected: Some("SSE-S3 or SSE-KMS".to_string()),
                        actual: Some("No encryption".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            // Check for versioning
            if !versioning_enabled {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::BestPractice,
                    severity: FindingSeverity::Low,
                    title: "S3 Bucket Versioning Not Enabled".to_string(),
                    description: format!(
                        "S3 bucket '{}' does not have versioning enabled.",
                        bucket_name
                    ),
                    remediation: Some("Enable versioning to protect against accidental deletions.".to_string()),
                    compliance_mappings: vec![],
                    affected_resource_arn: Some(format!("arn:aws:s3:::{}", bucket_name)),
                    evidence: Some(FindingEvidence {
                        description: "Bucket versioning is not enabled".to_string(),
                        raw_data: Some(serde_json::json!({"versioning": false})),
                        expected: Some("Versioning enabled".to_string()),
                        actual: Some("Versioning disabled".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }
        }

        Ok((resources, findings))
    }

    /// Scan EC2 using real AWS SDK
    async fn scan_compute_real(&self, regions: &[String]) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        for region in regions {
            let region_provider = aws_config::Region::new(region.clone());
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let ec2_client = aws_sdk_ec2::Client::new(&config);

            log::info!("Scanning EC2 instances in region {}...", region);

            let instances = ec2_client.describe_instances().send().await?;

            for reservation in instances.reservations() {
                for instance in reservation.instances() {
                    let instance_id = instance.instance_id().unwrap_or("unknown");
                    let resource_id = Uuid::new_v4().to_string();

                    let public_ip = instance.public_ip_address().map(|s| s.to_string());
                    let private_ip = instance.private_ip_address().map(|s| s.to_string());

                    // Get instance metadata options
                    let metadata_options = instance.metadata_options();
                    let imdsv2_required = metadata_options
                        .and_then(|m| m.http_tokens())
                        .map(|t| t.as_str() == "required")
                        .unwrap_or(false);

                    // Get instance name from tags
                    let name = instance.tags()
                        .iter()
                        .find(|t| t.key() == Some("Name"))
                        .and_then(|t| t.value().map(|s| s.to_string()));

                    // Check EBS encryption (simplified - would need describe_volumes for full check)
                    let ebs_encrypted = instance.block_device_mappings()
                        .iter()
                        .all(|m| m.ebs().and_then(|e| e.volume_id()).is_some());

                    // Get security groups
                    let security_groups: Vec<String> = instance.security_groups()
                        .iter()
                        .filter_map(|sg| sg.group_id().map(|s| s.to_string()))
                        .collect();

                    let state = instance.state()
                        .and_then(|s| s.name())
                        .map(|n| n.as_str().to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    resources.push(CloudResource {
                        id: resource_id.clone(),
                        resource_id: instance_id.to_string(),
                        resource_type: CloudResourceType::Ec2Instance,
                        provider: CloudProvider::Aws,
                        region: Some(region.clone()),
                        name,
                        arn: Some(format!("arn:aws:ec2:{}:instance/{}", region, instance_id)),
                        tags: HashMap::new(),
                        metadata: serde_json::json!({
                            "instance_type": instance.instance_type().map(|t| t.as_str()),
                            "public_ip": public_ip,
                            "private_ip": private_ip,
                            "security_groups": security_groups,
                            "imdsv2_required": imdsv2_required,
                            "ebs_encrypted": ebs_encrypted,
                            "state": state
                        }),
                        state: Some(state.clone()),
                        discovered_at: now,
                    });

                    // Check for IMDSv1 vulnerability
                    if !imdsv2_required && state == "running" {
                        findings.push(CloudFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: String::new(),
                            resource_id: Some(resource_id.clone()),
                            finding_type: FindingType::Misconfiguration,
                            severity: FindingSeverity::High,
                            title: "EC2 Instance Metadata Service v1 Enabled".to_string(),
                            description: format!(
                                "EC2 instance '{}' has IMDSv1 enabled. IMDSv1 is vulnerable to SSRF attacks.",
                                instance_id
                            ),
                            remediation: Some("Require IMDSv2 by setting HttpTokens to 'required'.".to_string()),
                            compliance_mappings: vec![
                                ComplianceMapping {
                                    framework: "CIS AWS".to_string(),
                                    control_id: "5.6".to_string(),
                                    control_title: Some("Ensure that EC2 Metadata Service only allows IMDSv2".to_string()),
                                },
                            ],
                            affected_resource_arn: Some(format!("arn:aws:ec2:{}:instance/{}", region, instance_id)),
                            evidence: Some(FindingEvidence {
                                description: "IMDSv2 is not required for this instance".to_string(),
                                raw_data: Some(serde_json::json!({"http_tokens": "optional"})),
                                expected: Some("IMDSv2 required".to_string()),
                                actual: Some("IMDSv1 allowed".to_string()),
                                collected_at: now,
                            }),
                            status: FindingStatus::Open,
                            created_at: now,
                        });
                    }

                    // Check for public IP exposure
                    if public_ip.is_some() && state == "running" {
                        findings.push(CloudFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: String::new(),
                            resource_id: Some(resource_id.clone()),
                            finding_type: FindingType::Exposure,
                            severity: FindingSeverity::Info,
                            title: "EC2 Instance with Public IP".to_string(),
                            description: format!(
                                "EC2 instance '{}' has a public IP address assigned. Review if public exposure is required.",
                                instance_id
                            ),
                            remediation: Some("Consider using private subnets with NAT gateway if public access is not required.".to_string()),
                            compliance_mappings: vec![],
                            affected_resource_arn: Some(format!("arn:aws:ec2:{}:instance/{}", region, instance_id)),
                            evidence: Some(FindingEvidence {
                                description: "Instance has public IP assigned".to_string(),
                                raw_data: Some(serde_json::json!({"public_ip": public_ip})),
                                expected: Some("Private IP only (if applicable)".to_string()),
                                actual: Some(format!("Public IP: {}", public_ip.unwrap_or_default())),
                                collected_at: now,
                            }),
                            status: FindingStatus::Open,
                            created_at: now,
                        });
                    }
                }
            }
        }

        Ok((resources, findings))
    }

    /// Scan Security Groups using real AWS SDK
    async fn scan_network_real(&self, regions: &[String]) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        for region in regions {
            let region_provider = aws_config::Region::new(region.clone());
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let ec2_client = aws_sdk_ec2::Client::new(&config);

            log::info!("Scanning security groups in region {}...", region);

            let sgs = ec2_client.describe_security_groups().send().await?;

            for sg in sgs.security_groups() {
                let sg_id = sg.group_id().unwrap_or("unknown");
                let sg_name = sg.group_name().unwrap_or("unknown");
                let vpc_id = sg.vpc_id().unwrap_or("unknown");
                let resource_id = Uuid::new_v4().to_string();

                // Analyze inbound rules
                let mut inbound_rules = Vec::new();
                let mut has_dangerous_rules = false;
                let mut dangerous_ports = Vec::new();

                for rule in sg.ip_permissions() {
                    let from_port = rule.from_port().unwrap_or(0);
                    let to_port = rule.to_port().unwrap_or(65535);
                    let protocol = rule.ip_protocol().unwrap_or("-1");

                    for ip_range in rule.ip_ranges() {
                        let cidr = ip_range.cidr_ip().unwrap_or("0.0.0.0/0");

                        inbound_rules.push(serde_json::json!({
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "source": cidr
                        }));

                        // Check for overly permissive rules
                        if cidr == "0.0.0.0/0" || cidr == "::/0" {
                            if protocol == "-1" || (from_port == 0 && to_port == 65535) {
                                has_dangerous_rules = true;
                                dangerous_ports.push("all".to_string());
                            } else if from_port == 22 || (from_port <= 22 && to_port >= 22) {
                                dangerous_ports.push("22 (SSH)".to_string());
                            } else if from_port == 3389 || (from_port <= 3389 && to_port >= 3389) {
                                dangerous_ports.push("3389 (RDP)".to_string());
                            } else if from_port == 3306 || (from_port <= 3306 && to_port >= 3306) {
                                dangerous_ports.push("3306 (MySQL)".to_string());
                            } else if from_port == 5432 || (from_port <= 5432 && to_port >= 5432) {
                                dangerous_ports.push("5432 (PostgreSQL)".to_string());
                            }
                        }
                    }
                }

                resources.push(CloudResource {
                    id: resource_id.clone(),
                    resource_id: sg_id.to_string(),
                    resource_type: CloudResourceType::SecurityGroup,
                    provider: CloudProvider::Aws,
                    region: Some(region.clone()),
                    name: Some(sg_name.to_string()),
                    arn: Some(format!("arn:aws:ec2:{}:security-group/{}", region, sg_id)),
                    tags: HashMap::new(),
                    metadata: serde_json::json!({
                        "vpc_id": vpc_id,
                        "inbound_rules": inbound_rules
                    }),
                    state: Some("Available".to_string()),
                    discovered_at: now,
                });

                // Create findings for dangerous rules
                if has_dangerous_rules || !dangerous_ports.is_empty() {
                    for port in &dangerous_ports {
                        let severity = if port == "all" {
                            FindingSeverity::Critical
                        } else if port.contains("SSH") || port.contains("RDP") {
                            FindingSeverity::Critical
                        } else {
                            FindingSeverity::High
                        };

                        findings.push(CloudFinding {
                            id: Uuid::new_v4().to_string(),
                            scan_id: String::new(),
                            resource_id: Some(resource_id.clone()),
                            finding_type: FindingType::Exposure,
                            severity,
                            title: format!("Security Group Allows {} from Any IP", port),
                            description: format!(
                                "Security group '{}' ({}) allows inbound access on {} from 0.0.0.0/0.",
                                sg_name, sg_id, port
                            ),
                            remediation: Some("Restrict access to specific IP addresses or CIDR ranges.".to_string()),
                            compliance_mappings: vec![
                                ComplianceMapping {
                                    framework: "CIS AWS".to_string(),
                                    control_id: "5.2".to_string(),
                                    control_title: Some("Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports".to_string()),
                                },
                            ],
                            affected_resource_arn: Some(format!("arn:aws:ec2:{}:security-group/{}", region, sg_id)),
                            evidence: Some(FindingEvidence {
                                description: format!("Inbound rule allows {} from any IP address", port),
                                raw_data: Some(serde_json::json!({"port": port, "source": "0.0.0.0/0"})),
                                expected: Some("Specific IP ranges".to_string()),
                                actual: Some("0.0.0.0/0 (any)".to_string()),
                                collected_at: now,
                            }),
                            status: FindingStatus::Open,
                            created_at: now,
                        });
                    }
                }
            }
        }

        Ok((resources, findings))
    }

    /// Scan RDS using real AWS SDK
    async fn scan_database_real(&self, regions: &[String]) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        for region in regions {
            let region_provider = aws_config::Region::new(region.clone());
            let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let rds_client = aws_sdk_rds::Client::new(&config);

            log::info!("Scanning RDS instances in region {}...", region);

            let instances = rds_client.describe_db_instances().send().await?;

            for db in instances.db_instances() {
                let db_id = db.db_instance_identifier().unwrap_or("unknown");
                let resource_id = Uuid::new_v4().to_string();

                let publicly_accessible = db.publicly_accessible().unwrap_or(false);
                let storage_encrypted = db.storage_encrypted().unwrap_or(false);
                let backup_retention = db.backup_retention_period().unwrap_or(0);
                let deletion_protection = db.deletion_protection().unwrap_or(false);
                let iam_auth = db.iam_database_authentication_enabled().unwrap_or(false);
                let engine = db.engine().unwrap_or("unknown");
                let engine_version = db.engine_version().unwrap_or("unknown");
                let auto_minor_upgrade = db.auto_minor_version_upgrade().unwrap_or(false);

                let arn = db.db_instance_arn().unwrap_or("unknown");
                let status = db.db_instance_status().unwrap_or("unknown");

                resources.push(CloudResource {
                    id: resource_id.clone(),
                    resource_id: db_id.to_string(),
                    resource_type: CloudResourceType::RdsInstance,
                    provider: CloudProvider::Aws,
                    region: Some(region.clone()),
                    name: Some(db_id.to_string()),
                    arn: Some(arn.to_string()),
                    tags: HashMap::new(),
                    metadata: serde_json::json!({
                        "engine": engine,
                        "engine_version": engine_version,
                        "publicly_accessible": publicly_accessible,
                        "storage_encrypted": storage_encrypted,
                        "auto_minor_version_upgrade": auto_minor_upgrade,
                        "backup_retention_period": backup_retention,
                        "deletion_protection": deletion_protection,
                        "iam_authentication": iam_auth
                    }),
                    state: Some(status.to_string()),
                    discovered_at: now,
                });

                // Check for public accessibility
                if publicly_accessible {
                    findings.push(CloudFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        resource_id: Some(resource_id.clone()),
                        finding_type: FindingType::Exposure,
                        severity: FindingSeverity::Critical,
                        title: "RDS Instance Publicly Accessible".to_string(),
                        description: format!(
                            "RDS instance '{}' is configured as publicly accessible.",
                            db_id
                        ),
                        remediation: Some("Modify the RDS instance to disable public accessibility.".to_string()),
                        compliance_mappings: vec![
                            ComplianceMapping {
                                framework: "CIS AWS".to_string(),
                                control_id: "2.3.1".to_string(),
                                control_title: Some("Ensure that RDS instances are not publicly accessible".to_string()),
                            },
                        ],
                        affected_resource_arn: Some(arn.to_string()),
                        evidence: Some(FindingEvidence {
                            description: "RDS instance is publicly accessible".to_string(),
                            raw_data: Some(serde_json::json!({"publicly_accessible": true})),
                            expected: Some("publicly_accessible: false".to_string()),
                            actual: Some("publicly_accessible: true".to_string()),
                            collected_at: now,
                        }),
                        status: FindingStatus::Open,
                        created_at: now,
                    });
                }

                // Check for encryption
                if !storage_encrypted {
                    findings.push(CloudFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        resource_id: Some(resource_id.clone()),
                        finding_type: FindingType::Misconfiguration,
                        severity: FindingSeverity::High,
                        title: "RDS Instance Storage Not Encrypted".to_string(),
                        description: format!(
                            "RDS instance '{}' does not have storage encryption enabled.",
                            db_id
                        ),
                        remediation: Some("Enable storage encryption for data at rest.".to_string()),
                        compliance_mappings: vec![
                            ComplianceMapping {
                                framework: "CIS AWS".to_string(),
                                control_id: "2.3.2".to_string(),
                                control_title: Some("Ensure that encryption is enabled for RDS instances".to_string()),
                            },
                        ],
                        affected_resource_arn: Some(arn.to_string()),
                        evidence: Some(FindingEvidence {
                            description: "Storage encryption is not enabled".to_string(),
                            raw_data: Some(serde_json::json!({"storage_encrypted": false})),
                            expected: Some("storage_encrypted: true".to_string()),
                            actual: Some("storage_encrypted: false".to_string()),
                            collected_at: now,
                        }),
                        status: FindingStatus::Open,
                        created_at: now,
                    });
                }

                // Check for backups
                if backup_retention == 0 {
                    findings.push(CloudFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        resource_id: Some(resource_id.clone()),
                        finding_type: FindingType::Misconfiguration,
                        severity: FindingSeverity::High,
                        title: "RDS Instance Backups Disabled".to_string(),
                        description: format!(
                            "RDS instance '{}' has backup retention set to 0 (disabled).",
                            db_id
                        ),
                        remediation: Some("Enable automated backups with at least 7 days retention.".to_string()),
                        compliance_mappings: vec![],
                        affected_resource_arn: Some(arn.to_string()),
                        evidence: Some(FindingEvidence {
                            description: "Backup retention period is 0".to_string(),
                            raw_data: Some(serde_json::json!({"backup_retention_period": 0})),
                            expected: Some("backup_retention_period: >= 7".to_string()),
                            actual: Some("backup_retention_period: 0".to_string()),
                            collected_at: now,
                        }),
                        status: FindingStatus::Open,
                        created_at: now,
                    });
                }

                // Check for deletion protection
                if !deletion_protection {
                    findings.push(CloudFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        resource_id: Some(resource_id.clone()),
                        finding_type: FindingType::BestPractice,
                        severity: FindingSeverity::Medium,
                        title: "RDS Instance Deletion Protection Disabled".to_string(),
                        description: format!(
                            "RDS instance '{}' does not have deletion protection enabled.",
                            db_id
                        ),
                        remediation: Some("Enable deletion protection for production databases.".to_string()),
                        compliance_mappings: vec![],
                        affected_resource_arn: Some(arn.to_string()),
                        evidence: Some(FindingEvidence {
                            description: "Deletion protection is not enabled".to_string(),
                            raw_data: Some(serde_json::json!({"deletion_protection": false})),
                            expected: Some("deletion_protection: true".to_string()),
                            actual: Some("deletion_protection: false".to_string()),
                            collected_at: now,
                        }),
                        status: FindingStatus::Open,
                        created_at: now,
                    });
                }
            }
        }

        Ok((resources, findings))
    }

    // Demo mode generation methods (keeping existing implementation for testing)
    fn generate_demo_iam_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo IAM User with issues
        let user_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: user_id.clone(),
            resource_id: "AIDAEXAMPLE123".to_string(),
            resource_type: CloudResourceType::IamUser,
            provider: CloudProvider::Aws,
            region: Some("global".to_string()),
            name: Some("legacy-admin-user".to_string()),
            arn: Some("arn:aws:iam::123456789012:user/legacy-admin-user".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "has_mfa": false,
                "access_key_age_days": 365,
                "has_console_access": true,
                "attached_policies": ["AdministratorAccess"]
            }),
            state: Some("Active".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(user_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Critical,
            title: "IAM User Without MFA".to_string(),
            description: "IAM user 'legacy-admin-user' has console access but MFA is not enabled.".to_string(),
            remediation: Some("Enable MFA for all IAM users with console access.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS AWS".to_string(),
                    control_id: "1.10".to_string(),
                    control_title: Some("Ensure multi-factor authentication (MFA) is enabled for all IAM users".to_string()),
                },
            ],
            affected_resource_arn: Some("arn:aws:iam::123456789012:user/legacy-admin-user".to_string()),
            evidence: Some(FindingEvidence {
                description: "User has console access but no MFA device configured".to_string(),
                raw_data: Some(serde_json::json!({"mfa_devices": [], "password_enabled": true})),
                expected: Some("MFA enabled".to_string()),
                actual: Some("No MFA configured".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    fn generate_demo_storage_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let bucket_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: bucket_id.clone(),
            resource_id: "customer-data-backup".to_string(),
            resource_type: CloudResourceType::S3Bucket,
            provider: CloudProvider::Aws,
            region: Some("us-east-1".to_string()),
            name: Some("customer-data-backup".to_string()),
            arn: Some("arn:aws:s3:::customer-data-backup".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "public_access_block": {"block_public_acls": false},
                "versioning": false,
                "encryption": "none"
            }),
            state: Some("Available".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(bucket_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "S3 Bucket with Public Access Enabled".to_string(),
            description: "S3 bucket 'customer-data-backup' has public access block settings disabled.".to_string(),
            remediation: Some("Enable S3 Block Public Access settings.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("arn:aws:s3:::customer-data-backup".to_string()),
            evidence: None,
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    fn generate_demo_compute_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let instance_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: instance_id.clone(),
            resource_id: "i-0abc123def456789".to_string(),
            resource_type: CloudResourceType::Ec2Instance,
            provider: CloudProvider::Aws,
            region: Some("us-east-1".to_string()),
            name: Some("web-server-prod-01".to_string()),
            arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456789".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "imdsv2_required": false,
                "public_ip": "203.0.113.45"
            }),
            state: Some("running".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(instance_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "EC2 Instance Metadata Service v1 Enabled".to_string(),
            description: "EC2 instance has IMDSv1 enabled, vulnerable to SSRF attacks.".to_string(),
            remediation: Some("Require IMDSv2 by setting HttpTokens to 'required'.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456789".to_string()),
            evidence: None,
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    fn generate_demo_network_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let sg_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: sg_id.clone(),
            resource_id: "sg-0abc123def456789".to_string(),
            resource_type: CloudResourceType::SecurityGroup,
            provider: CloudProvider::Aws,
            region: Some("us-east-1".to_string()),
            name: Some("web-server-sg".to_string()),
            arn: Some("arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123def456789".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "inbound_rules": [
                    {"protocol": "tcp", "from_port": 22, "to_port": 22, "source": "0.0.0.0/0"}
                ]
            }),
            state: Some("Available".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sg_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Security Group Allows SSH from Any IP".to_string(),
            description: "Security group allows inbound SSH (port 22) from 0.0.0.0/0.".to_string(),
            remediation: Some("Restrict SSH access to specific IP addresses.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123def456789".to_string()),
            evidence: None,
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    fn generate_demo_database_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let rds_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: rds_id.clone(),
            resource_id: "production-db".to_string(),
            resource_type: CloudResourceType::RdsInstance,
            provider: CloudProvider::Aws,
            region: Some("us-east-1".to_string()),
            name: Some("production-db".to_string()),
            arn: Some("arn:aws:rds:us-east-1:123456789012:db:production-db".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "publicly_accessible": true,
                "storage_encrypted": false,
                "backup_retention_period": 0
            }),
            state: Some("available".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(rds_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "RDS Instance Publicly Accessible".to_string(),
            description: "RDS instance 'production-db' is configured as publicly accessible.".to_string(),
            remediation: Some("Disable public accessibility for the RDS instance.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("arn:aws:rds:us-east-1:123456789012:db:production-db".to_string()),
            evidence: None,
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }
}

#[async_trait::async_trait]
impl CloudScanner for AwsScanner {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }

    async fn scan_iam(&self, config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("AWS IAM scan running in demo mode");
            return Ok(self.generate_demo_iam_resources());
        }

        log::info!("AWS IAM scan running with real AWS SDK");
        self.scan_iam_real(&config.regions).await
    }

    async fn scan_storage(&self, config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("AWS Storage scan running in demo mode");
            return Ok(self.generate_demo_storage_resources());
        }

        log::info!("AWS Storage scan running with real AWS SDK");
        self.scan_storage_real(&config.regions).await
    }

    async fn scan_compute(&self, config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("AWS Compute scan running in demo mode");
            return Ok(self.generate_demo_compute_resources());
        }

        log::info!("AWS Compute scan running with real AWS SDK");
        self.scan_compute_real(&config.regions).await
    }

    async fn scan_network(&self, config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("AWS Network scan running in demo mode");
            return Ok(self.generate_demo_network_resources());
        }

        log::info!("AWS Network scan running with real AWS SDK");
        self.scan_network_real(&config.regions).await
    }

    async fn scan_database(&self, config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.demo_mode {
            log::info!("AWS Database scan running in demo mode");
            return Ok(self.generate_demo_database_resources());
        }

        log::info!("AWS Database scan running with real AWS SDK");
        self.scan_database_real(&config.regions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aws_demo_scan() {
        let scanner = AwsScanner::new(true);
        let config = CloudScanConfig {
            provider: CloudProvider::Aws,
            regions: vec!["us-east-1".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
            demo_mode: true,
        };

        let (resources, findings) = scanner.run_scan(&config).await.unwrap();

        assert!(!resources.is_empty(), "Demo scan should return resources");
        assert!(!findings.is_empty(), "Demo scan should return findings");
    }

    #[test]
    fn test_provider_display() {
        assert_eq!(CloudProvider::Aws.to_string(), "aws");
    }
}
