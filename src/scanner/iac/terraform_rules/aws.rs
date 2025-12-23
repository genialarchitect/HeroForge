//! AWS Terraform Security Rules
//!
//! Comprehensive security rules for AWS resources based on:
//! - CIS AWS Foundations Benchmark
//! - AWS Well-Architected Framework
//! - AWS Security Best Practices

use crate::scanner::iac::rules::{RuleMatcher, RuleMatch};
use crate::scanner::iac::types::*;
use lazy_static::lazy_static;
use regex::Regex;

// ============================================================================
// AWS S3 Rules (AWS_S3_001 - AWS_S3_020)
// ============================================================================

lazy_static! {
    // S3 patterns
    static ref S3_NO_VERSIONING: Regex = Regex::new(r#"(?i)versioning\s*\{\s*enabled\s*=\s*false"#).unwrap();
    static ref S3_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?:(?!server_side_encryption_configuration).)*\}"#).unwrap();
    static ref S3_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{(?:(?!logging).)*\}"#).unwrap();
    static ref S3_PUBLIC_POLICY: Regex = Regex::new(r#"(?i)"Principal"\s*:\s*["']\*["']"#).unwrap();
    static ref S3_NO_LIFECYCLE: Regex = Regex::new(r#"resource\s+"aws_s3_bucket"\s+"[^"]+"(?:(?!lifecycle_rule).)*\}"#).unwrap();
    static ref S3_NO_MFA_DELETE: Regex = Regex::new(r#"(?i)mfa_delete\s*=\s*false"#).unwrap();
    static ref S3_IGNORE_PUBLIC_ACLS_FALSE: Regex = Regex::new(r#"(?i)ignore_public_acls\s*=\s*false"#).unwrap();
    static ref S3_BLOCK_PUBLIC_ACLS_FALSE: Regex = Regex::new(r#"(?i)block_public_acls\s*=\s*false"#).unwrap();
    static ref S3_BLOCK_PUBLIC_POLICY_FALSE: Regex = Regex::new(r#"(?i)block_public_policy\s*=\s*false"#).unwrap();
    static ref S3_RESTRICT_PUBLIC_BUCKETS_FALSE: Regex = Regex::new(r#"(?i)restrict_public_buckets\s*=\s*false"#).unwrap();

    // EC2/VPC patterns
    static ref EC2_IMDS_V1: Regex = Regex::new(r#"(?i)http_tokens\s*=\s*["']?optional["']?"#).unwrap();
    static ref EC2_NO_IMDS_HOP_LIMIT: Regex = Regex::new(r#"(?i)http_put_response_hop_limit\s*=\s*[2-9]|[1-9][0-9]+"#).unwrap();
    static ref EC2_DETAILED_MONITORING_DISABLED: Regex = Regex::new(r#"(?i)monitoring\s*=\s*false"#).unwrap();
    static ref EC2_PUBLIC_IP: Regex = Regex::new(r#"(?i)associate_public_ip_address\s*=\s*true"#).unwrap();
    static ref EC2_USER_DATA_SECRET: Regex = Regex::new(r#"(?i)user_data\s*=.*(?:password|secret|key|token)"#).unwrap();
    static ref LAUNCH_TEMPLATE_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)resource\s+"aws_launch_template".*block_device_mappings\s*\{[^}]*encrypted\s*=\s*false"#).unwrap();
    static ref EBS_SNAPSHOT_PUBLIC: Regex = Regex::new(r#"(?i)resource\s+"aws_ebs_snapshot"[^}]*create_volume_permission[^}]*group\s*=\s*["']?all["']?"#).unwrap();
    static ref AMI_PUBLIC: Regex = Regex::new(r#"(?i)resource\s+"aws_ami"[^}]*public\s*=\s*true"#).unwrap();

    // VPC patterns
    static ref DEFAULT_VPC_USAGE: Regex = Regex::new(r#"(?i)resource\s+"aws_default_vpc""#).unwrap();
    static ref VPC_FLOW_LOGS_DISABLED: Regex = Regex::new(r#"(?i)resource\s+"aws_vpc"\s+"[^"]+"\s*\{(?:(?!aws_flow_log).)*$"#).unwrap();
    static ref SG_EGRESS_ALL: Regex = Regex::new(r#"(?i)egress\s*\{[^}]*protocol\s*=\s*["']-1["'][^}]*cidr_blocks\s*=\s*\[[^]]*"0\.0\.0\.0/0"[^}]*\}"#).unwrap();
    static ref NACL_ALLOW_ALL: Regex = Regex::new(r#"(?i)rule_action\s*=\s*["']?allow["']?[^}]*cidr_block\s*=\s*["']?0\.0\.0\.0/0["']?[^}]*protocol\s*=\s*["']-1["']?"#).unwrap();

    // IAM patterns
    static ref IAM_USER_POLICY_DIRECT: Regex = Regex::new(r#"(?i)resource\s+"aws_iam_user_policy""#).unwrap();
    static ref IAM_USER_POLICY_ATTACHMENT: Regex = Regex::new(r#"(?i)resource\s+"aws_iam_user_policy_attachment""#).unwrap();
    static ref IAM_NO_MFA: Regex = Regex::new(r#"(?i)"aws:MultiFactorAuthPresent"\s*:\s*["']?false["']?"#).unwrap();
    static ref IAM_ASSUME_ROLE_WILDCARD: Regex = Regex::new(r#"(?i)assume_role_policy[^}]*"Principal"\s*:\s*\{[^}]*"AWS"\s*:\s*["']\*["']"#).unwrap();
    static ref IAM_PASSWORD_POLICY_WEAK: Regex = Regex::new(r#"(?i)minimum_password_length\s*=\s*([0-9]|1[0-3])(?!\d)"#).unwrap();
    static ref IAM_PASSWORD_NO_UPPERCASE: Regex = Regex::new(r#"(?i)require_uppercase_characters\s*=\s*false"#).unwrap();
    static ref IAM_PASSWORD_NO_LOWERCASE: Regex = Regex::new(r#"(?i)require_lowercase_characters\s*=\s*false"#).unwrap();
    static ref IAM_PASSWORD_NO_NUMBERS: Regex = Regex::new(r#"(?i)require_numbers\s*=\s*false"#).unwrap();
    static ref IAM_PASSWORD_NO_SYMBOLS: Regex = Regex::new(r#"(?i)require_symbols\s*=\s*false"#).unwrap();
    static ref IAM_ADMIN_POLICY: Regex = Regex::new(r#"(?i)arn:aws:iam::aws:policy/AdministratorAccess"#).unwrap();
    static ref IAM_PASSROLE_STAR: Regex = Regex::new(r#"(?i)"Action"\s*:\s*\[?[^]]*"iam:PassRole"[^]]*\][^}]*"Resource"\s*:\s*["']\*["']"#).unwrap();

    // RDS patterns
    static ref RDS_PUBLIC: Regex = Regex::new(r#"(?i)publicly_accessible\s*=\s*true"#).unwrap();
    static ref RDS_NO_BACKUP: Regex = Regex::new(r#"(?i)backup_retention_period\s*=\s*0"#).unwrap();
    static ref RDS_NO_DELETION_PROTECTION: Regex = Regex::new(r#"(?i)deletion_protection\s*=\s*false"#).unwrap();
    static ref RDS_NO_IAM_AUTH: Regex = Regex::new(r#"(?i)iam_database_authentication_enabled\s*=\s*false"#).unwrap();
    static ref RDS_NO_ENHANCED_MONITORING: Regex = Regex::new(r#"(?i)monitoring_interval\s*=\s*0"#).unwrap();
    static ref RDS_DEFAULT_PORT: Regex = Regex::new(r#"(?i)port\s*=\s*(3306|5432|1433|1521)"#).unwrap();
    static ref RDS_NO_MULTI_AZ: Regex = Regex::new(r#"(?i)multi_az\s*=\s*false"#).unwrap();
    static ref RDS_PERFORMANCE_INSIGHTS_DISABLED: Regex = Regex::new(r#"(?i)performance_insights_enabled\s*=\s*false"#).unwrap();
    static ref RDS_AUTO_MINOR_UPGRADE_DISABLED: Regex = Regex::new(r#"(?i)auto_minor_version_upgrade\s*=\s*false"#).unwrap();
    static ref RDS_COPY_TAGS_DISABLED: Regex = Regex::new(r#"(?i)copy_tags_to_snapshot\s*=\s*false"#).unwrap();

    // EKS patterns
    static ref EKS_PUBLIC_ENDPOINT: Regex = Regex::new(r#"(?i)endpoint_public_access\s*=\s*true"#).unwrap();
    static ref EKS_NO_PRIVATE_ENDPOINT: Regex = Regex::new(r#"(?i)endpoint_private_access\s*=\s*false"#).unwrap();
    static ref EKS_NO_SECRETS_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_eks_cluster"\s+"[^"]+"\s*\{(?:(?!encryption_config).)*\}"#).unwrap();
    static ref EKS_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_eks_cluster"\s+"[^"]+"\s*\{(?:(?!enabled_cluster_log_types).)*\}"#).unwrap();
    static ref EKS_OUTDATED_VERSION: Regex = Regex::new(r#"(?i)version\s*=\s*["']?1\.(2[0-6]|1[0-9]|[0-9])["']?"#).unwrap();

    // Lambda patterns
    static ref LAMBDA_NO_VPC: Regex = Regex::new(r#"resource\s+"aws_lambda_function"\s+"[^"]+"\s*\{(?:(?!vpc_config).)*\}"#).unwrap();
    static ref LAMBDA_ENV_SECRETS: Regex = Regex::new(r#"(?i)environment\s*\{[^}]*variables\s*=\s*\{[^}]*(?:password|secret|key|token)\s*="#).unwrap();
    static ref LAMBDA_WILDCARD_PERMISSION: Regex = Regex::new(r#"(?i)resource\s+"aws_lambda_permission"[^}]*principal\s*=\s*["']\*["']"#).unwrap();
    static ref LAMBDA_NO_DLQ: Regex = Regex::new(r#"resource\s+"aws_lambda_function"\s+"[^"]+"\s*\{(?:(?!dead_letter_config).)*\}"#).unwrap();
    static ref LAMBDA_NO_TRACING: Regex = Regex::new(r#"resource\s+"aws_lambda_function"\s+"[^"]+"\s*\{(?:(?!tracing_config).)*\}"#).unwrap();

    // KMS patterns
    static ref KMS_KEY_ROTATION_DISABLED: Regex = Regex::new(r#"(?i)enable_key_rotation\s*=\s*false"#).unwrap();
    static ref KMS_PUBLIC_ACCESS: Regex = Regex::new(r#"(?i)resource\s+"aws_kms_key"[^}]*"Principal"\s*:\s*["']\*["']"#).unwrap();
    static ref KMS_WILDCARD_USAGE: Regex = Regex::new(r#"(?i)"Action"\s*:\s*\[?"kms:\*"\]?"#).unwrap();

    // CloudWatch/CloudTrail patterns
    static ref CLOUDWATCH_LOG_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_cloudwatch_log_group"\s+"[^"]+"\s*\{(?:(?!kms_key_id).)*\}"#).unwrap();
    static ref CLOUDWATCH_LOG_NO_RETENTION: Regex = Regex::new(r#"resource\s+"aws_cloudwatch_log_group"\s+"[^"]+"\s*\{(?:(?!retention_in_days).)*\}"#).unwrap();
    static ref CLOUDTRAIL_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_cloudtrail"\s+"[^"]+"\s*\{(?:(?!kms_key_id).)*\}"#).unwrap();
    static ref CLOUDTRAIL_NO_LOG_VALIDATION: Regex = Regex::new(r#"(?i)enable_log_file_validation\s*=\s*false"#).unwrap();
    static ref CLOUDTRAIL_NOT_MULTI_REGION: Regex = Regex::new(r#"(?i)is_multi_region_trail\s*=\s*false"#).unwrap();

    // SNS/SQS patterns
    static ref SNS_TOPIC_PUBLIC: Regex = Regex::new(r#"(?i)resource\s+"aws_sns_topic_policy"[^}]*"Principal"\s*:\s*["']\*["']"#).unwrap();
    static ref SNS_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_sns_topic"\s+"[^"]+"\s*\{(?:(?!kms_master_key_id).)*\}"#).unwrap();
    static ref SQS_QUEUE_PUBLIC: Regex = Regex::new(r#"(?i)resource\s+"aws_sqs_queue_policy"[^}]*"Principal"\s*:\s*["']\*["']"#).unwrap();
    static ref SQS_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_sqs_queue"\s+"[^"]+"\s*\{(?:(?!kms_master_key_id).)*\}"#).unwrap();

    // ElastiCache patterns
    static ref ELASTICACHE_NO_ENCRYPTION_TRANSIT: Regex = Regex::new(r#"(?i)transit_encryption_enabled\s*=\s*false"#).unwrap();
    static ref ELASTICACHE_NO_ENCRYPTION_REST: Regex = Regex::new(r#"(?i)at_rest_encryption_enabled\s*=\s*false"#).unwrap();
    static ref ELASTICACHE_NO_AUTH: Regex = Regex::new(r#"resource\s+"aws_elasticache_replication_group"\s+"[^"]+"\s*\{(?:(?!auth_token).)*\}"#).unwrap();

    // ALB/ELB patterns
    static ref ALB_HTTP_LISTENER: Regex = Regex::new(r#"(?i)resource\s+"aws_lb_listener"[^}]*protocol\s*=\s*["']HTTP["']"#).unwrap();
    static ref ALB_NO_ACCESS_LOGS: Regex = Regex::new(r#"resource\s+"aws_lb"\s+"[^"]+"\s*\{(?:(?!access_logs).)*\}"#).unwrap();
    static ref ALB_DROP_INVALID_HEADERS: Regex = Regex::new(r#"(?i)drop_invalid_header_fields\s*=\s*false"#).unwrap();
    static ref ALB_DELETION_PROTECTION_DISABLED: Regex = Regex::new(r#"(?i)enable_deletion_protection\s*=\s*false"#).unwrap();
    static ref ALB_INSECURE_SSL: Regex = Regex::new(r#"(?i)ssl_policy\s*=\s*["']ELBSecurityPolicy-2016-08["']"#).unwrap();

    // Elasticsearch patterns
    static ref ES_PUBLIC_ENDPOINT: Regex = Regex::new(r#"resource\s+"aws_elasticsearch_domain"\s+"[^"]+"\s*\{(?:(?!vpc_options).)*\}"#).unwrap();
    static ref ES_NO_ENCRYPTION_REST: Regex = Regex::new(r#"(?i)encrypt_at_rest\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref ES_NO_NODE_TO_NODE_ENCRYPTION: Regex = Regex::new(r#"(?i)node_to_node_encryption\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref ES_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_elasticsearch_domain"\s+"[^"]+"\s*\{(?:(?!log_publishing_options).)*\}"#).unwrap();
    static ref ES_ENFORCE_HTTPS_DISABLED: Regex = Regex::new(r#"(?i)enforce_https\s*=\s*false"#).unwrap();

    // DynamoDB patterns
    static ref DYNAMODB_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_dynamodb_table"\s+"[^"]+"\s*\{(?:(?!server_side_encryption).)*\}"#).unwrap();
    static ref DYNAMODB_NO_PITR: Regex = Regex::new(r#"(?i)point_in_time_recovery\s*\{[^}]*enabled\s*=\s*false"#).unwrap();

    // Redshift patterns
    static ref REDSHIFT_PUBLIC: Regex = Regex::new(r#"(?i)publicly_accessible\s*=\s*true"#).unwrap();
    static ref REDSHIFT_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)encrypted\s*=\s*false"#).unwrap();
    static ref REDSHIFT_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_redshift_cluster"\s+"[^"]+"\s*\{(?:(?!logging).)*\}"#).unwrap();
    static ref REDSHIFT_NO_ENHANCED_VPC: Regex = Regex::new(r#"(?i)enhanced_vpc_routing\s*=\s*false"#).unwrap();

    // ECR patterns
    static ref ECR_NO_SCAN: Regex = Regex::new(r#"(?i)image_scanning_configuration\s*\{[^}]*scan_on_push\s*=\s*false"#).unwrap();
    static ref ECR_MUTABLE_TAGS: Regex = Regex::new(r#"(?i)image_tag_mutability\s*=\s*["']MUTABLE["']"#).unwrap();
    static ref ECR_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"aws_ecr_repository"\s+"[^"]+"\s*\{(?:(?!encryption_configuration).)*\}"#).unwrap();

    // API Gateway patterns
    static ref APIGW_NO_AUTH: Regex = Regex::new(r#"(?i)authorization\s*=\s*["']NONE["']"#).unwrap();
    static ref APIGW_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_api_gateway_stage"\s+"[^"]+"\s*\{(?:(?!access_log_settings).)*\}"#).unwrap();
    static ref APIGW_NO_SSL_CERT: Regex = Regex::new(r#"resource\s+"aws_api_gateway_stage"\s+"[^"]+"\s*\{(?:(?!client_certificate_id).)*\}"#).unwrap();
    static ref APIGW_NO_WAF: Regex = Regex::new(r#"resource\s+"aws_api_gateway_stage"\s+"[^"]+"\s*\{(?:(?!web_acl_arn).)*\}"#).unwrap();
    static ref APIGW_NO_XRAY: Regex = Regex::new(r#"(?i)xray_tracing_enabled\s*=\s*false"#).unwrap();
    static ref APIGW_CACHE_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)cache_data_encrypted\s*=\s*false"#).unwrap();

    // Secrets Manager patterns
    static ref SECRETS_NO_ROTATION: Regex = Regex::new(r#"resource\s+"aws_secretsmanager_secret"\s+"[^"]+"\s*\{(?:(?!rotation).)*\}"#).unwrap();
    static ref SECRETS_NO_KMS: Regex = Regex::new(r#"resource\s+"aws_secretsmanager_secret"\s+"[^"]+"\s*\{(?:(?!kms_key_id).)*\}"#).unwrap();

    // SSM patterns
    static ref SSM_PARAM_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)type\s*=\s*["']String["']"#).unwrap();

    // Cognito patterns
    static ref COGNITO_NO_MFA: Regex = Regex::new(r#"(?i)mfa_configuration\s*=\s*["']OFF["']"#).unwrap();
    static ref COGNITO_WEAK_PASSWORD: Regex = Regex::new(r#"(?i)minimum_length\s*=\s*([0-7])(?!\d)"#).unwrap();

    // Config/GuardDuty patterns
    static ref CONFIG_NOT_ENABLED: Regex = Regex::new(r#"(?i)resource\s+"aws_config_configuration_recorder".*is_enabled\s*=\s*false"#).unwrap();
    static ref GUARDDUTY_NOT_ENABLED: Regex = Regex::new(r#"(?i)resource\s+"aws_guardduty_detector".*enable\s*=\s*false"#).unwrap();

    // WAF patterns
    static ref WAF_NO_LOGGING: Regex = Regex::new(r#"resource\s+"aws_wafv2_web_acl"\s+"[^"]+"\s*\{(?:(?!logging_configuration).)*\}"#).unwrap();
}

// ============================================================================
// Rule Implementations
// ============================================================================

macro_rules! impl_aws_rule {
    ($name:ident, $id:expr, $rule_name:expr, $desc:expr, $severity:expr, $category:expr,
     $remediation:expr, $doc_url:expr, $pattern:expr, $resource_type:expr, $msg:expr) => {
        pub struct $name;

        impl RuleMatcher for $name {
            fn id(&self) -> &str { $id }
            fn name(&self) -> &str { $rule_name }
            fn description(&self) -> &str { $desc }
            fn severity(&self) -> IacSeverity { $severity }
            fn category(&self) -> IacFindingCategory { $category }
            fn platforms(&self) -> &[IacPlatform] { &[IacPlatform::Terraform] }
            fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Aws] }
            fn remediation(&self) -> &str { $remediation }
            fn documentation_url(&self) -> Option<&str> { Some($doc_url) }
            fn compliance_mappings(&self) -> Vec<IacComplianceMapping> { vec![] }

            fn check(&self, content: &str, _filename: &str, _platform: IacPlatform) -> Vec<RuleMatch> {
                let mut matches = Vec::new();
                for (line_num, line) in content.lines().enumerate() {
                    if $pattern.is_match(line) {
                        matches.push(RuleMatch {
                            line_start: (line_num + 1) as i32,
                            line_end: (line_num + 1) as i32,
                            code_snippet: line.to_string(),
                            resource_type: Some($resource_type),
                            resource_name: None,
                            message: Some($msg.to_string()),
                        });
                    }
                }
                matches
            }
        }
    };
}

// S3 Rules
impl_aws_rule!(AwsS3BlockPublicAclsRule, "AWS_S3_001", "S3 Block Public ACLs Disabled",
    "S3 bucket has block_public_acls set to false, allowing public ACLs",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set block_public_acls = true in aws_s3_bucket_public_access_block",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    S3_BLOCK_PUBLIC_ACLS_FALSE, IacResourceType::AwsS3Bucket,
    "S3 public access block not configured to block public ACLs");

impl_aws_rule!(AwsS3IgnorePublicAclsRule, "AWS_S3_002", "S3 Ignore Public ACLs Disabled",
    "S3 bucket has ignore_public_acls set to false",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set ignore_public_acls = true in aws_s3_bucket_public_access_block",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    S3_IGNORE_PUBLIC_ACLS_FALSE, IacResourceType::AwsS3Bucket,
    "S3 public access block not configured to ignore public ACLs");

impl_aws_rule!(AwsS3BlockPublicPolicyRule, "AWS_S3_003", "S3 Block Public Policy Disabled",
    "S3 bucket has block_public_policy set to false",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set block_public_policy = true in aws_s3_bucket_public_access_block",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    S3_BLOCK_PUBLIC_POLICY_FALSE, IacResourceType::AwsS3Bucket,
    "S3 public access block not configured to block public policies");

impl_aws_rule!(AwsS3RestrictPublicBucketsRule, "AWS_S3_004", "S3 Restrict Public Buckets Disabled",
    "S3 bucket has restrict_public_buckets set to false",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set restrict_public_buckets = true in aws_s3_bucket_public_access_block",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
    S3_RESTRICT_PUBLIC_BUCKETS_FALSE, IacResourceType::AwsS3Bucket,
    "S3 public access block not configured to restrict public buckets");

impl_aws_rule!(AwsS3VersioningDisabledRule, "AWS_S3_005", "S3 Versioning Disabled",
    "S3 bucket versioning is disabled",
    IacSeverity::Medium, IacFindingCategory::InsecureDefault,
    "Enable versioning with versioning { enabled = true }",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
    S3_NO_VERSIONING, IacResourceType::AwsS3Bucket,
    "S3 bucket versioning is disabled");

impl_aws_rule!(AwsS3MfaDeleteDisabledRule, "AWS_S3_006", "S3 MFA Delete Disabled",
    "S3 bucket MFA delete is not enabled for versioned bucket",
    IacSeverity::Medium, IacFindingCategory::InsecureDefault,
    "Enable MFA delete with versioning { mfa_delete = true }",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html",
    S3_NO_MFA_DELETE, IacResourceType::AwsS3Bucket,
    "S3 bucket MFA delete is disabled");

// EC2/VPC Rules
impl_aws_rule!(AwsEc2ImdsV1Rule, "AWS_EC2_001", "EC2 Instance Metadata Service v1 Enabled",
    "EC2 instance allows IMDSv1 which is vulnerable to SSRF attacks",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set http_tokens = 'required' in metadata_options to enforce IMDSv2",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    EC2_IMDS_V1, IacResourceType::AwsEc2Instance,
    "IMDSv1 is enabled, vulnerable to SSRF attacks");

impl_aws_rule!(AwsEc2DetailedMonitoringRule, "AWS_EC2_002", "EC2 Detailed Monitoring Disabled",
    "EC2 instance detailed monitoring is disabled",
    IacSeverity::Low, IacFindingCategory::MissingLogging,
    "Set monitoring = true to enable detailed CloudWatch monitoring",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html",
    EC2_DETAILED_MONITORING_DISABLED, IacResourceType::AwsEc2Instance,
    "EC2 detailed monitoring is disabled");

impl_aws_rule!(AwsEc2PublicIpRule, "AWS_EC2_003", "EC2 Instance with Public IP",
    "EC2 instance is configured with a public IP address",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set associate_public_ip_address = false and use NAT gateway for outbound access",
    "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html",
    EC2_PUBLIC_IP, IacResourceType::AwsEc2Instance,
    "EC2 instance has public IP enabled");

impl_aws_rule!(AwsDefaultVpcRule, "AWS_VPC_001", "Default VPC Usage",
    "Using default VPC which has less restrictive network settings",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Create a custom VPC with proper network segmentation instead of using the default VPC",
    "https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
    DEFAULT_VPC_USAGE, IacResourceType::AwsVpc,
    "Using AWS default VPC");

impl_aws_rule!(AwsSgEgressAllRule, "AWS_SG_001", "Security Group Allows All Egress",
    "Security group allows all outbound traffic to 0.0.0.0/0",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Restrict egress rules to only required destinations and ports",
    "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
    SG_EGRESS_ALL, IacResourceType::AwsSecurityGroup,
    "Security group allows unrestricted egress");

// IAM Rules
impl_aws_rule!(AwsIamUserPolicyDirectRule, "AWS_IAM_001", "IAM Policy Attached Directly to User",
    "IAM policy is attached directly to a user instead of a group or role",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Attach policies to groups or roles instead of directly to users",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    IAM_USER_POLICY_DIRECT, IacResourceType::AwsIamPolicy,
    "IAM policy attached directly to user");

impl_aws_rule!(AwsIamUserPolicyAttachmentRule, "AWS_IAM_002", "IAM User Policy Attachment",
    "Policy attached directly to user via aws_iam_user_policy_attachment",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Use aws_iam_group_policy_attachment or aws_iam_role_policy_attachment instead",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
    IAM_USER_POLICY_ATTACHMENT, IacResourceType::AwsIamPolicy,
    "Policy attached directly to IAM user");

impl_aws_rule!(AwsIamAdminPolicyRule, "AWS_IAM_003", "IAM AdministratorAccess Policy Used",
    "AdministratorAccess managed policy is attached, granting full AWS access",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Create custom policies with only required permissions following least privilege",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
    IAM_ADMIN_POLICY, IacResourceType::AwsIamPolicy,
    "AdministratorAccess policy grants excessive permissions");

impl_aws_rule!(AwsIamPassRoleStarRule, "AWS_IAM_004", "IAM PassRole with Wildcard Resource",
    "iam:PassRole action with wildcard resource allows passing any role",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Specify exact role ARNs instead of using wildcard for PassRole",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
    IAM_PASSROLE_STAR, IacResourceType::AwsIamPolicy,
    "iam:PassRole with * resource allows privilege escalation");

impl_aws_rule!(AwsIamPasswordPolicyWeakRule, "AWS_IAM_005", "IAM Weak Password Policy",
    "IAM password policy has minimum length less than 14 characters",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set minimum_password_length to at least 14 characters",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
    IAM_PASSWORD_POLICY_WEAK, IacResourceType::AwsIamPolicy,
    "Password policy minimum length is too short");

impl_aws_rule!(AwsIamAssumeRoleWildcardRule, "AWS_IAM_006", "IAM Assume Role with Wildcard Principal",
    "IAM role trust policy allows any AWS principal to assume the role",
    IacSeverity::Critical, IacFindingCategory::IamMisconfiguration,
    "Specify exact AWS account IDs or ARNs in the Principal element",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
    IAM_ASSUME_ROLE_WILDCARD, IacResourceType::AwsIamRole,
    "Role can be assumed by any AWS principal");

// RDS Rules
impl_aws_rule!(AwsRdsPublicRule, "AWS_RDS_001", "RDS Instance Publicly Accessible",
    "RDS instance is publicly accessible from the internet",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Set publicly_accessible = false and use private subnets",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
    RDS_PUBLIC, IacResourceType::AwsRdsInstance,
    "RDS instance is publicly accessible");

impl_aws_rule!(AwsRdsNoBackupRule, "AWS_RDS_002", "RDS Backup Disabled",
    "RDS automated backups are disabled (retention = 0)",
    IacSeverity::High, IacFindingCategory::DataProtection,
    "Set backup_retention_period to at least 7 days",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
    RDS_NO_BACKUP, IacResourceType::AwsRdsInstance,
    "RDS automated backups are disabled");

impl_aws_rule!(AwsRdsNoDeletionProtectionRule, "AWS_RDS_003", "RDS Deletion Protection Disabled",
    "RDS instance deletion protection is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set deletion_protection = true to prevent accidental deletion",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html",
    RDS_NO_DELETION_PROTECTION, IacResourceType::AwsRdsInstance,
    "RDS deletion protection is disabled");

impl_aws_rule!(AwsRdsNoIamAuthRule, "AWS_RDS_004", "RDS IAM Authentication Disabled",
    "RDS IAM database authentication is disabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set iam_database_authentication_enabled = true",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html",
    RDS_NO_IAM_AUTH, IacResourceType::AwsRdsInstance,
    "RDS IAM authentication is disabled");

impl_aws_rule!(AwsRdsNoMultiAzRule, "AWS_RDS_005", "RDS Multi-AZ Disabled",
    "RDS instance is not configured for Multi-AZ deployment",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set multi_az = true for high availability",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html",
    RDS_NO_MULTI_AZ, IacResourceType::AwsRdsInstance,
    "RDS Multi-AZ deployment is disabled");

impl_aws_rule!(AwsRdsPerformanceInsightsRule, "AWS_RDS_006", "RDS Performance Insights Disabled",
    "RDS Performance Insights is not enabled",
    IacSeverity::Low, IacFindingCategory::MissingLogging,
    "Set performance_insights_enabled = true for monitoring",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html",
    RDS_PERFORMANCE_INSIGHTS_DISABLED, IacResourceType::AwsRdsInstance,
    "RDS Performance Insights is disabled");

impl_aws_rule!(AwsRdsAutoMinorUpgradeRule, "AWS_RDS_007", "RDS Auto Minor Version Upgrade Disabled",
    "RDS automatic minor version upgrades are disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set auto_minor_version_upgrade = true for security patches",
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html",
    RDS_AUTO_MINOR_UPGRADE_DISABLED, IacResourceType::AwsRdsInstance,
    "RDS auto minor version upgrade is disabled");

// EKS Rules
impl_aws_rule!(AwsEksPublicEndpointRule, "AWS_EKS_001", "EKS Public Endpoint Enabled",
    "EKS cluster API server endpoint is publicly accessible",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set endpoint_public_access = false and use private endpoint",
    "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
    EKS_PUBLIC_ENDPOINT, IacResourceType::AwsEks,
    "EKS cluster has public endpoint access enabled");

impl_aws_rule!(AwsEksNoPrivateEndpointRule, "AWS_EKS_002", "EKS Private Endpoint Disabled",
    "EKS cluster private endpoint access is disabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set endpoint_private_access = true for internal access",
    "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
    EKS_NO_PRIVATE_ENDPOINT, IacResourceType::AwsEks,
    "EKS cluster private endpoint access is disabled");

impl_aws_rule!(AwsEksOutdatedVersionRule, "AWS_EKS_003", "EKS Outdated Kubernetes Version",
    "EKS cluster is running an outdated Kubernetes version",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Upgrade to a supported Kubernetes version (1.27+)",
    "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html",
    EKS_OUTDATED_VERSION, IacResourceType::AwsEks,
    "EKS cluster running outdated Kubernetes version");

// Lambda Rules
impl_aws_rule!(AwsLambdaEnvSecretsRule, "AWS_LAMBDA_001", "Lambda Environment Variable Secrets",
    "Lambda function has secrets in environment variables",
    IacSeverity::Critical, IacFindingCategory::HardcodedSecret,
    "Use AWS Secrets Manager or Parameter Store instead of environment variables",
    "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html",
    LAMBDA_ENV_SECRETS, IacResourceType::AwsLambdaFunction,
    "Secrets detected in Lambda environment variables");

impl_aws_rule!(AwsLambdaWildcardPermissionRule, "AWS_LAMBDA_002", "Lambda Wildcard Permission",
    "Lambda function permission allows invocation from any principal",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Specify exact principal ARN instead of wildcard",
    "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
    LAMBDA_WILDCARD_PERMISSION, IacResourceType::AwsLambdaFunction,
    "Lambda allows invocation from any principal");

// KMS Rules
impl_aws_rule!(AwsKmsKeyRotationRule, "AWS_KMS_001", "KMS Key Rotation Disabled",
    "KMS key automatic rotation is disabled",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set enable_key_rotation = true for automatic annual rotation",
    "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
    KMS_KEY_ROTATION_DISABLED, IacResourceType::AwsKmsKey,
    "KMS key rotation is disabled");

impl_aws_rule!(AwsKmsWildcardUsageRule, "AWS_KMS_002", "KMS Wildcard Action",
    "KMS policy uses wildcard (kms:*) action",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Specify exact KMS actions needed instead of wildcard",
    "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
    KMS_WILDCARD_USAGE, IacResourceType::AwsKmsKey,
    "KMS policy uses wildcard action");

// CloudTrail Rules
impl_aws_rule!(AwsCloudTrailNoLogValidationRule, "AWS_CT_001", "CloudTrail Log Validation Disabled",
    "CloudTrail log file validation is disabled",
    IacSeverity::Medium, IacFindingCategory::MissingLogging,
    "Set enable_log_file_validation = true",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html",
    CLOUDTRAIL_NO_LOG_VALIDATION, IacResourceType::AwsCloudwatch,
    "CloudTrail log file validation is disabled");

impl_aws_rule!(AwsCloudTrailNotMultiRegionRule, "AWS_CT_002", "CloudTrail Not Multi-Region",
    "CloudTrail is not configured as multi-region trail",
    IacSeverity::Medium, IacFindingCategory::MissingLogging,
    "Set is_multi_region_trail = true for comprehensive logging",
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
    CLOUDTRAIL_NOT_MULTI_REGION, IacResourceType::AwsCloudwatch,
    "CloudTrail not configured as multi-region");

// SNS/SQS Rules
impl_aws_rule!(AwsSnsTpoicPublicRule, "AWS_SNS_001", "SNS Topic Publicly Accessible",
    "SNS topic policy allows access from any principal (*)",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Restrict SNS topic policy Principal to specific AWS accounts",
    "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html",
    SNS_TOPIC_PUBLIC, IacResourceType::AwsSns,
    "SNS topic is publicly accessible");

impl_aws_rule!(AwsSqsQueuePublicRule, "AWS_SQS_001", "SQS Queue Publicly Accessible",
    "SQS queue policy allows access from any principal (*)",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Restrict SQS queue policy Principal to specific AWS accounts",
    "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html",
    SQS_QUEUE_PUBLIC, IacResourceType::AwsSqs,
    "SQS queue is publicly accessible");

// ElastiCache Rules
impl_aws_rule!(AwsElastiCacheNoEncryptionTransitRule, "AWS_EC_001", "ElastiCache Transit Encryption Disabled",
    "ElastiCache cluster does not have encryption in transit enabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set transit_encryption_enabled = true",
    "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
    ELASTICACHE_NO_ENCRYPTION_TRANSIT, IacResourceType::AwsElasticache,
    "ElastiCache transit encryption is disabled");

impl_aws_rule!(AwsElastiCacheNoEncryptionRestRule, "AWS_EC_002", "ElastiCache At-Rest Encryption Disabled",
    "ElastiCache cluster does not have encryption at rest enabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set at_rest_encryption_enabled = true",
    "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html",
    ELASTICACHE_NO_ENCRYPTION_REST, IacResourceType::AwsElasticache,
    "ElastiCache at-rest encryption is disabled");

// ALB/ELB Rules
impl_aws_rule!(AwsAlbHttpListenerRule, "AWS_ALB_001", "ALB HTTP Listener",
    "Application Load Balancer has HTTP listener instead of HTTPS",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Use HTTPS listener with valid SSL certificate",
    "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
    ALB_HTTP_LISTENER, IacResourceType::AwsElb,
    "ALB has HTTP listener without TLS");

impl_aws_rule!(AwsAlbDeletionProtectionRule, "AWS_ALB_002", "ALB Deletion Protection Disabled",
    "Application Load Balancer deletion protection is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set enable_deletion_protection = true",
    "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
    ALB_DELETION_PROTECTION_DISABLED, IacResourceType::AwsElb,
    "ALB deletion protection is disabled");

impl_aws_rule!(AwsAlbInsecureSslRule, "AWS_ALB_003", "ALB Insecure SSL Policy",
    "ALB uses outdated SSL policy with weak ciphers",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Use ELBSecurityPolicy-TLS13-1-2-2021-06 or newer",
    "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
    ALB_INSECURE_SSL, IacResourceType::AwsElb,
    "ALB using outdated SSL policy");

impl_aws_rule!(AwsAlbDropInvalidHeadersRule, "AWS_ALB_004", "ALB Not Dropping Invalid Headers",
    "ALB is not configured to drop invalid HTTP headers",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set drop_invalid_header_fields = true",
    "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
    ALB_DROP_INVALID_HEADERS, IacResourceType::AwsElb,
    "ALB not dropping invalid HTTP headers");

// Elasticsearch Rules
impl_aws_rule!(AwsEsNoEncryptionRestRule, "AWS_ES_001", "Elasticsearch At-Rest Encryption Disabled",
    "Elasticsearch domain encryption at rest is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set encrypt_at_rest { enabled = true }",
    "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
    ES_NO_ENCRYPTION_REST, IacResourceType::AwsElasticsearch,
    "Elasticsearch at-rest encryption is disabled");

impl_aws_rule!(AwsEsNoNodeToNodeEncryptionRule, "AWS_ES_002", "Elasticsearch Node-to-Node Encryption Disabled",
    "Elasticsearch domain node-to-node encryption is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set node_to_node_encryption { enabled = true }",
    "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
    ES_NO_NODE_TO_NODE_ENCRYPTION, IacResourceType::AwsElasticsearch,
    "Elasticsearch node-to-node encryption is disabled");

impl_aws_rule!(AwsEsEnforceHttpsRule, "AWS_ES_003", "Elasticsearch HTTPS Not Enforced",
    "Elasticsearch domain does not enforce HTTPS",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set domain_endpoint_options { enforce_https = true }",
    "https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
    ES_ENFORCE_HTTPS_DISABLED, IacResourceType::AwsElasticsearch,
    "Elasticsearch HTTPS is not enforced");

// DynamoDB Rules
impl_aws_rule!(AwsDynamoDbNoEncryptionRule, "AWS_DDB_001", "DynamoDB Encryption Not Configured",
    "DynamoDB table does not have server-side encryption configured",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Add server_side_encryption { enabled = true }",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
    DYNAMODB_NO_ENCRYPTION, IacResourceType::AwsDynamodb,
    "DynamoDB encryption not explicitly configured");

impl_aws_rule!(AwsDynamoDbNoPitrRule, "AWS_DDB_002", "DynamoDB Point-in-Time Recovery Disabled",
    "DynamoDB table point-in-time recovery is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set point_in_time_recovery { enabled = true }",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
    DYNAMODB_NO_PITR, IacResourceType::AwsDynamodb,
    "DynamoDB point-in-time recovery is disabled");

// ECR Rules
impl_aws_rule!(AwsEcrNoScanRule, "AWS_ECR_001", "ECR Image Scanning Disabled",
    "ECR repository scan on push is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set image_scanning_configuration { scan_on_push = true }",
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
    ECR_NO_SCAN, IacResourceType::AwsEcr,
    "ECR scan on push is disabled");

impl_aws_rule!(AwsEcrMutableTagsRule, "AWS_ECR_002", "ECR Mutable Image Tags",
    "ECR repository allows mutable image tags",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set image_tag_mutability = 'IMMUTABLE'",
    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",
    ECR_MUTABLE_TAGS, IacResourceType::AwsEcr,
    "ECR image tags are mutable");

// API Gateway Rules
impl_aws_rule!(AwsApigwNoAuthRule, "AWS_APIGW_001", "API Gateway No Authorization",
    "API Gateway method has no authorization configured",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Set authorization to AWS_IAM, COGNITO_USER_POOLS, or CUSTOM",
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html",
    APIGW_NO_AUTH, IacResourceType::AwsApiGateway,
    "API Gateway method has no authorization");

impl_aws_rule!(AwsApigwNoXrayRule, "AWS_APIGW_002", "API Gateway X-Ray Tracing Disabled",
    "API Gateway X-Ray tracing is disabled",
    IacSeverity::Low, IacFindingCategory::MissingLogging,
    "Set xray_tracing_enabled = true",
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-xray.html",
    APIGW_NO_XRAY, IacResourceType::AwsApiGateway,
    "API Gateway X-Ray tracing is disabled");

impl_aws_rule!(AwsApigwCacheNoEncryptionRule, "AWS_APIGW_003", "API Gateway Cache Not Encrypted",
    "API Gateway cache data encryption is disabled",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set cache_data_encrypted = true in method_settings",
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html",
    APIGW_CACHE_NO_ENCRYPTION, IacResourceType::AwsApiGateway,
    "API Gateway cache encryption is disabled");

// Secrets Manager Rules
impl_aws_rule!(AwsSecretsNoKmsRule, "AWS_SM_001", "Secrets Manager No KMS Key",
    "Secrets Manager secret does not use a customer-managed KMS key",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Specify kms_key_id with a customer-managed key",
    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html",
    SECRETS_NO_KMS, IacResourceType::AwsSecretsManager,
    "Secrets Manager using default encryption");

// Cognito Rules
impl_aws_rule!(AwsCognitoNoMfaRule, "AWS_COG_001", "Cognito MFA Disabled",
    "Cognito user pool MFA is disabled",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Set mfa_configuration = 'ON' or 'OPTIONAL'",
    "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html",
    COGNITO_NO_MFA, IacResourceType::AwsCognito,
    "Cognito MFA is disabled");

impl_aws_rule!(AwsCognitoWeakPasswordRule, "AWS_COG_002", "Cognito Weak Password Policy",
    "Cognito user pool has weak password policy (< 8 characters)",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set minimum_length to at least 8 characters",
    "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-policies.html",
    COGNITO_WEAK_PASSWORD, IacResourceType::AwsCognito,
    "Cognito password policy is too weak");

// Config/GuardDuty Rules
impl_aws_rule!(AwsGuardDutyDisabledRule, "AWS_GD_001", "GuardDuty Disabled",
    "GuardDuty detector is disabled",
    IacSeverity::High, IacFindingCategory::MissingLogging,
    "Set enable = true in aws_guardduty_detector",
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html",
    GUARDDUTY_NOT_ENABLED, IacResourceType::AwsGuardDuty,
    "GuardDuty is disabled");

// Redshift Rules
impl_aws_rule!(AwsRedshiftPublicRule, "AWS_RS_001", "Redshift Cluster Publicly Accessible",
    "Redshift cluster is publicly accessible",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Set publicly_accessible = false",
    "https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
    REDSHIFT_PUBLIC, IacResourceType::AwsRedshift,
    "Redshift cluster is publicly accessible");

impl_aws_rule!(AwsRedshiftNoEncryptionRule, "AWS_RS_002", "Redshift Cluster Not Encrypted",
    "Redshift cluster encryption is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set encrypted = true",
    "https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html",
    REDSHIFT_NO_ENCRYPTION, IacResourceType::AwsRedshift,
    "Redshift cluster is not encrypted");

impl_aws_rule!(AwsRedshiftNoEnhancedVpcRule, "AWS_RS_003", "Redshift Enhanced VPC Routing Disabled",
    "Redshift enhanced VPC routing is disabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set enhanced_vpc_routing = true",
    "https://docs.aws.amazon.com/redshift/latest/mgmt/enhanced-vpc-routing.html",
    REDSHIFT_NO_ENHANCED_VPC, IacResourceType::AwsRedshift,
    "Redshift enhanced VPC routing is disabled");

// WAF Rules
impl_aws_rule!(AwsWafNoLoggingRule, "AWS_WAF_001", "WAF Logging Disabled",
    "WAF web ACL does not have logging configured",
    IacSeverity::Medium, IacFindingCategory::MissingLogging,
    "Add logging_configuration block to aws_wafv2_web_acl",
    "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html",
    WAF_NO_LOGGING, IacResourceType::AwsWaf,
    "WAF logging is not configured");

/// Get all AWS rules
pub fn get_aws_rules() -> Vec<Box<dyn RuleMatcher>> {
    vec![
        // S3 Rules
        Box::new(AwsS3BlockPublicAclsRule),
        Box::new(AwsS3IgnorePublicAclsRule),
        Box::new(AwsS3BlockPublicPolicyRule),
        Box::new(AwsS3RestrictPublicBucketsRule),
        Box::new(AwsS3VersioningDisabledRule),
        Box::new(AwsS3MfaDeleteDisabledRule),
        // EC2/VPC Rules
        Box::new(AwsEc2ImdsV1Rule),
        Box::new(AwsEc2DetailedMonitoringRule),
        Box::new(AwsEc2PublicIpRule),
        Box::new(AwsDefaultVpcRule),
        Box::new(AwsSgEgressAllRule),
        // IAM Rules
        Box::new(AwsIamUserPolicyDirectRule),
        Box::new(AwsIamUserPolicyAttachmentRule),
        Box::new(AwsIamAdminPolicyRule),
        Box::new(AwsIamPassRoleStarRule),
        Box::new(AwsIamPasswordPolicyWeakRule),
        Box::new(AwsIamAssumeRoleWildcardRule),
        // RDS Rules
        Box::new(AwsRdsPublicRule),
        Box::new(AwsRdsNoBackupRule),
        Box::new(AwsRdsNoDeletionProtectionRule),
        Box::new(AwsRdsNoIamAuthRule),
        Box::new(AwsRdsNoMultiAzRule),
        Box::new(AwsRdsPerformanceInsightsRule),
        Box::new(AwsRdsAutoMinorUpgradeRule),
        // EKS Rules
        Box::new(AwsEksPublicEndpointRule),
        Box::new(AwsEksNoPrivateEndpointRule),
        Box::new(AwsEksOutdatedVersionRule),
        // Lambda Rules
        Box::new(AwsLambdaEnvSecretsRule),
        Box::new(AwsLambdaWildcardPermissionRule),
        // KMS Rules
        Box::new(AwsKmsKeyRotationRule),
        Box::new(AwsKmsWildcardUsageRule),
        // CloudTrail Rules
        Box::new(AwsCloudTrailNoLogValidationRule),
        Box::new(AwsCloudTrailNotMultiRegionRule),
        // SNS/SQS Rules
        Box::new(AwsSnsTpoicPublicRule),
        Box::new(AwsSqsQueuePublicRule),
        // ElastiCache Rules
        Box::new(AwsElastiCacheNoEncryptionTransitRule),
        Box::new(AwsElastiCacheNoEncryptionRestRule),
        // ALB/ELB Rules
        Box::new(AwsAlbHttpListenerRule),
        Box::new(AwsAlbDeletionProtectionRule),
        Box::new(AwsAlbInsecureSslRule),
        Box::new(AwsAlbDropInvalidHeadersRule),
        // Elasticsearch Rules
        Box::new(AwsEsNoEncryptionRestRule),
        Box::new(AwsEsNoNodeToNodeEncryptionRule),
        Box::new(AwsEsEnforceHttpsRule),
        // DynamoDB Rules
        Box::new(AwsDynamoDbNoEncryptionRule),
        Box::new(AwsDynamoDbNoPitrRule),
        // ECR Rules
        Box::new(AwsEcrNoScanRule),
        Box::new(AwsEcrMutableTagsRule),
        // API Gateway Rules
        Box::new(AwsApigwNoAuthRule),
        Box::new(AwsApigwNoXrayRule),
        Box::new(AwsApigwCacheNoEncryptionRule),
        // Secrets Manager Rules
        Box::new(AwsSecretsNoKmsRule),
        // Cognito Rules
        Box::new(AwsCognitoNoMfaRule),
        Box::new(AwsCognitoWeakPasswordRule),
        // Config/GuardDuty Rules
        Box::new(AwsGuardDutyDisabledRule),
        // Redshift Rules
        Box::new(AwsRedshiftPublicRule),
        Box::new(AwsRedshiftNoEncryptionRule),
        Box::new(AwsRedshiftNoEnhancedVpcRule),
        // WAF Rules
        Box::new(AwsWafNoLoggingRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_rules_count() {
        let rules = get_aws_rules();
        assert!(rules.len() >= 50, "Expected at least 50 AWS rules, got {}", rules.len());
    }

    #[test]
    fn test_s3_public_acl_detection() {
        let rule = AwsS3BlockPublicAclsRule;
        let content = r#"
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id
  block_public_acls = false
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_rds_public_detection() {
        let rule = AwsRdsPublicRule;
        let content = r#"
resource "aws_db_instance" "example" {
  allocated_storage = 20
  engine = "mysql"
  publicly_accessible = true
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_eks_public_endpoint_detection() {
        let rule = AwsEksPublicEndpointRule;
        let content = r#"
resource "aws_eks_cluster" "example" {
  name = "example"
  vpc_config {
    endpoint_public_access = true
  }
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }
}
