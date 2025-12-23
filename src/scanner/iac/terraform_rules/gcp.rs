//! GCP Terraform Security Rules
//!
//! Comprehensive security rules for GCP resources based on:
//! - CIS GCP Foundations Benchmark
//! - Google Cloud Security Best Practices
//! - Google Cloud Architecture Framework

use crate::scanner::iac::rules::{RuleMatcher, RuleMatch};
use crate::scanner::iac::types::*;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Storage patterns
    static ref GCS_UNIFORM_ACCESS_DISABLED: Regex = Regex::new(r#"(?i)uniform_bucket_level_access\s*=\s*false"#).unwrap();
    static ref GCS_PUBLIC_ACCESS: Regex = Regex::new(r#"(?i)allUsers|allAuthenticatedUsers"#).unwrap();
    static ref GCS_NO_VERSIONING: Regex = Regex::new(r#"(?i)versioning\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref GCS_NO_RETENTION: Regex = Regex::new(r#"resource\s+"google_storage_bucket"\s+"[^"]+"\s*\{(?:(?!retention_policy).)*\}"#).unwrap();
    static ref GCS_NO_LOGGING: Regex = Regex::new(r#"resource\s+"google_storage_bucket"\s+"[^"]+"\s*\{(?:(?!logging).)*\}"#).unwrap();
    static ref GCS_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"google_storage_bucket"\s+"[^"]+"\s*\{(?:(?!encryption).)*\}"#).unwrap();
    static ref GCS_PUBLIC_PREVENTION_UNSPECIFIED: Regex = Regex::new(r#"(?i)public_access_prevention\s*=\s*["']unspecified["']"#).unwrap();

    // Compute patterns
    static ref COMPUTE_PUBLIC_IP: Regex = Regex::new(r#"(?i)access_config\s*\{"#).unwrap();
    static ref COMPUTE_DEFAULT_SA: Regex = Regex::new(r#"(?i)service_account\s*\{[^}]*email\s*=\s*["'][^"']*-compute@developer\.gserviceaccount\.com["']"#).unwrap();
    static ref COMPUTE_NO_SHIELDED_VM: Regex = Regex::new(r#"resource\s+"google_compute_instance"\s+"[^"]+"\s*\{(?:(?!shielded_instance_config).)*\}"#).unwrap();
    static ref COMPUTE_VTPM_DISABLED: Regex = Regex::new(r#"(?i)enable_vtpm\s*=\s*false"#).unwrap();
    static ref COMPUTE_INTEGRITY_DISABLED: Regex = Regex::new(r#"(?i)enable_integrity_monitoring\s*=\s*false"#).unwrap();
    static ref COMPUTE_SERIAL_PORT_ENABLED: Regex = Regex::new(r#"(?i)serial-port-enable\s*=\s*["']?true["']?"#).unwrap();
    static ref COMPUTE_PROJECT_SSH_KEYS: Regex = Regex::new(r#"(?i)block_project_ssh_keys\s*=\s*false"#).unwrap();
    static ref COMPUTE_OS_LOGIN_DISABLED: Regex = Regex::new(r#"(?i)enable-oslogin\s*=\s*["']?FALSE["']?"#).unwrap();
    static ref COMPUTE_IP_FORWARDING: Regex = Regex::new(r#"(?i)can_ip_forward\s*=\s*true"#).unwrap();
    static ref COMPUTE_NO_CONFIDENTIAL_VM: Regex = Regex::new(r#"resource\s+"google_compute_instance"\s+"[^"]+"\s*\{(?:(?!confidential_instance_config).)*\}"#).unwrap();
    static ref COMPUTE_DISK_NO_ENCRYPTION: Regex = Regex::new(r#"resource\s+"google_compute_disk"\s+"[^"]+"\s*\{(?:(?!disk_encryption_key).)*\}"#).unwrap();

    // Network patterns
    static ref FIREWALL_SSH_OPEN: Regex = Regex::new(r#"(?i)allow\s*\{[^}]*ports\s*=\s*\[[^]]*"22"[^}]*source_ranges\s*=\s*\[[^]]*"0\.0\.0\.0/0""#).unwrap();
    static ref FIREWALL_RDP_OPEN: Regex = Regex::new(r#"(?i)allow\s*\{[^}]*ports\s*=\s*\[[^]]*"3389"[^}]*source_ranges\s*=\s*\[[^]]*"0\.0\.0\.0/0""#).unwrap();
    static ref FIREWALL_ALL_OPEN: Regex = Regex::new(r#"(?i)source_ranges\s*=\s*\[[^]]*"0\.0\.0\.0/0"[^]]*\][^}]*allow\s*\{[^}]*protocol\s*=\s*["']all["']"#).unwrap();
    static ref FIREWALL_LOGGING_DISABLED: Regex = Regex::new(r#"resource\s+"google_compute_firewall"\s+"[^"]+"\s*\{(?:(?!log_config).)*\}"#).unwrap();
    static ref VPC_LEGACY_NETWORK: Regex = Regex::new(r#"(?i)auto_create_subnetworks\s*=\s*true"#).unwrap();
    static ref VPC_NO_FLOW_LOGS: Regex = Regex::new(r#"resource\s+"google_compute_subnetwork"\s+"[^"]+"\s*\{(?:(?!log_config).)*\}"#).unwrap();
    static ref VPC_PRIVATE_ACCESS_DISABLED: Regex = Regex::new(r#"(?i)private_ip_google_access\s*=\s*false"#).unwrap();
    static ref LOAD_BALANCER_NO_SSL_POLICY: Regex = Regex::new(r#"resource\s+"google_compute_target_https_proxy"\s+"[^"]+"\s*\{(?:(?!ssl_policy).)*\}"#).unwrap();

    // IAM patterns
    static ref IAM_BINDING_PUBLIC: Regex = Regex::new(r#"(?i)members?\s*=\s*\[[^]]*"allUsers"[^]]*\]"#).unwrap();
    static ref IAM_BINDING_AUTH_USERS: Regex = Regex::new(r#"(?i)members?\s*=\s*\[[^]]*"allAuthenticatedUsers"[^]]*\]"#).unwrap();
    static ref IAM_PRIMITIVE_ROLES: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/(owner|editor|viewer)["']"#).unwrap();
    static ref IAM_SA_KEY_CREATED: Regex = Regex::new(r#"resource\s+"google_service_account_key""#).unwrap();
    static ref IAM_SA_ADMIN_ROLE: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/iam\.serviceAccountAdmin["']"#).unwrap();
    static ref IAM_TOKEN_CREATOR_ROLE: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/iam\.serviceAccountTokenCreator["']"#).unwrap();
    static ref IAM_USER_MANAGED_KEY: Regex = Regex::new(r#"(?i)key_algorithm\s*=\s*["']KEY_ALG_RSA_1024["']"#).unwrap();

    // GKE patterns
    static ref GKE_LEGACY_ABAC: Regex = Regex::new(r#"(?i)enable_legacy_abac\s*=\s*true"#).unwrap();
    static ref GKE_BASIC_AUTH: Regex = Regex::new(r#"(?i)master_auth\s*\{[^}]*username\s*="#).unwrap();
    static ref GKE_CLIENT_CERT: Regex = Regex::new(r#"(?i)issue_client_certificate\s*=\s*true"#).unwrap();
    static ref GKE_NO_PRIVATE_CLUSTER: Regex = Regex::new(r#"(?i)enable_private_nodes\s*=\s*false"#).unwrap();
    static ref GKE_PUBLIC_ENDPOINT: Regex = Regex::new(r#"(?i)enable_private_endpoint\s*=\s*false"#).unwrap();
    static ref GKE_NO_NETWORK_POLICY: Regex = Regex::new(r#"(?i)network_policy\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref GKE_NO_POD_SECURITY_POLICY: Regex = Regex::new(r#"(?i)pod_security_policy_config\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref GKE_NO_WORKLOAD_IDENTITY: Regex = Regex::new(r#"resource\s+"google_container_cluster"\s+"[^"]+"\s*\{(?:(?!workload_identity_config).)*\}"#).unwrap();
    static ref GKE_DEFAULT_NODE_SA: Regex = Regex::new(r#"(?i)node_config\s*\{(?:(?!service_account).)*\}"#).unwrap();
    static ref GKE_NO_SHIELDED_NODES: Regex = Regex::new(r#"(?i)enable_shielded_nodes\s*=\s*false"#).unwrap();
    static ref GKE_DASHBOARD_ENABLED: Regex = Regex::new(r#"(?i)kubernetes_dashboard\s*\{[^}]*disabled\s*=\s*false"#).unwrap();
    static ref GKE_NO_BINARY_AUTH: Regex = Regex::new(r#"(?i)enable_binary_authorization\s*=\s*false"#).unwrap();
    static ref GKE_INTRANODE_VISIBILITY_DISABLED: Regex = Regex::new(r#"(?i)enable_intranode_visibility\s*=\s*false"#).unwrap();
    static ref GKE_RELEASE_CHANNEL_UNSPECIFIED: Regex = Regex::new(r#"(?i)release_channel\s*\{[^}]*channel\s*=\s*["']UNSPECIFIED["']"#).unwrap();
    static ref GKE_NO_DATABASE_ENCRYPTION: Regex = Regex::new(r#"resource\s+"google_container_cluster"\s+"[^"]+"\s*\{(?:(?!database_encryption).)*\}"#).unwrap();
    static ref GKE_NODE_NO_METADATA_CONCEALMENT: Regex = Regex::new(r#"resource\s+"google_container_node_pool"\s+"[^"]+"\s*\{(?:(?!workload_metadata_config).)*\}"#).unwrap();

    // Cloud SQL patterns
    static ref SQL_PUBLIC_IP: Regex = Regex::new(r#"(?i)ipv4_enabled\s*=\s*true"#).unwrap();
    static ref SQL_NO_SSL: Regex = Regex::new(r#"(?i)require_ssl\s*=\s*false"#).unwrap();
    static ref SQL_NO_BACKUP: Regex = Regex::new(r#"(?i)backup_configuration\s*\{[^}]*enabled\s*=\s*false"#).unwrap();
    static ref SQL_PITR_DISABLED: Regex = Regex::new(r#"(?i)point_in_time_recovery_enabled\s*=\s*false"#).unwrap();
    static ref SQL_AUTHORIZED_NETWORKS_OPEN: Regex = Regex::new(r#"(?i)authorized_networks\s*\{[^}]*value\s*=\s*["']0\.0\.0\.0/0["']"#).unwrap();
    static ref SQL_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_sql_database_instance"\s+"[^"]+"\s*\{(?:(?!encryption_key_name).)*\}"#).unwrap();
    static ref SQL_LOCAL_FLAGS_ENABLED: Regex = Regex::new(r#"(?i)database_flags\s*\{[^}]*name\s*=\s*["']local_infile["'][^}]*value\s*=\s*["']on["']"#).unwrap();

    // BigQuery patterns
    static ref BQ_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_bigquery_dataset"\s+"[^"]+"\s*\{(?:(?!default_encryption_configuration).)*\}"#).unwrap();
    static ref BQ_PUBLIC_ACCESS: Regex = Regex::new(r#"(?i)access\s*\{[^}]*special_group\s*=\s*["']allAuthenticatedUsers["']"#).unwrap();
    static ref BQ_TABLE_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_bigquery_table"\s+"[^"]+"\s*\{(?:(?!encryption_configuration).)*\}"#).unwrap();

    // Cloud Functions patterns
    static ref FUNCTION_PUBLIC_INVOKER: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/cloudfunctions\.invoker["'][^}]*member\s*=\s*["']allUsers["']"#).unwrap();
    static ref FUNCTION_INGRESS_ALL: Regex = Regex::new(r#"(?i)ingress_settings\s*=\s*["']ALLOW_ALL["']"#).unwrap();
    static ref FUNCTION_NO_VPC_CONNECTOR: Regex = Regex::new(r#"resource\s+"google_cloudfunctions_function"\s+"[^"]+"\s*\{(?:(?!vpc_connector).)*\}"#).unwrap();

    // Cloud Run patterns
    static ref RUN_PUBLIC_INVOKER: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/run\.invoker["'][^}]*member\s*=\s*["']allUsers["']"#).unwrap();
    static ref RUN_INGRESS_ALL: Regex = Regex::new(r#"(?i)ingress\s*=\s*["']all["']"#).unwrap();
    static ref RUN_NO_VPC_CONNECTOR: Regex = Regex::new(r#"resource\s+"google_cloud_run_service"\s+"[^"]+"\s*\{(?:(?!vpc_connector).)*\}"#).unwrap();

    // Pub/Sub patterns
    static ref PUBSUB_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_pubsub_topic"\s+"[^"]+"\s*\{(?:(?!kms_key_name).)*\}"#).unwrap();
    static ref PUBSUB_PUBLIC_SUBSCRIPTION: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/pubsub\.subscriber["'][^}]*member\s*=\s*["']allUsers["']"#).unwrap();

    // KMS patterns
    static ref KMS_PUBLIC_KEY: Regex = Regex::new(r#"(?i)role\s*=\s*["']roles/cloudkms\.[^"']+["'][^}]*member\s*=\s*["']allUsers["']"#).unwrap();
    static ref KMS_NO_ROTATION: Regex = Regex::new(r#"resource\s+"google_kms_crypto_key"\s+"[^"]+"\s*\{(?:(?!rotation_period).)*\}"#).unwrap();
    static ref KMS_WEAK_ALGORITHM: Regex = Regex::new(r#"(?i)algorithm\s*=\s*["']RSA_SIGN_PKCS1_2048_SHA256["']"#).unwrap();

    // Logging/Monitoring patterns
    static ref LOG_SINK_NO_FILTER: Regex = Regex::new(r#"resource\s+"google_logging_project_sink"\s+"[^"]+"\s*\{(?:(?!filter).)*\}"#).unwrap();
    static ref AUDIT_LOG_DISABLED: Regex = Regex::new(r#"(?i)audit_log_config\s*\{[^}]*log_type\s*=\s*["']ADMIN_READ["'][^}]*exempted_members"#).unwrap();

    // Secret Manager patterns
    static ref SECRET_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_secret_manager_secret"\s+"[^"]+"\s*\{(?:(?!customer_managed_encryption).)*\}"#).unwrap();
    static ref SECRET_NO_ROTATION: Regex = Regex::new(r#"resource\s+"google_secret_manager_secret"\s+"[^"]+"\s*\{(?:(?!rotation).)*\}"#).unwrap();

    // Cloud Armor patterns
    static ref ARMOR_ADAPTIVE_PROTECTION_DISABLED: Regex = Regex::new(r#"(?i)adaptive_protection_config\s*\{[^}]*layer_7_ddos_defense_config\s*\{[^}]*enable\s*=\s*false"#).unwrap();
    static ref ARMOR_LOG_DISABLED: Regex = Regex::new(r#"resource\s+"google_compute_security_policy"\s+"[^"]+"\s*\{(?:(?!log_config).)*\}"#).unwrap();

    // Dataproc patterns
    static ref DATAPROC_PUBLIC_IP: Regex = Regex::new(r#"(?i)internal_ip_only\s*=\s*false"#).unwrap();
    static ref DATAPROC_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_dataproc_cluster"\s+"[^"]+"\s*\{(?:(?!kms_key_name).)*\}"#).unwrap();

    // Spanner patterns
    static ref SPANNER_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_spanner_database"\s+"[^"]+"\s*\{(?:(?!encryption_config).)*\}"#).unwrap();

    // Filestore patterns
    static ref FILESTORE_NO_CMEK: Regex = Regex::new(r#"resource\s+"google_filestore_instance"\s+"[^"]+"\s*\{(?:(?!kms_key_name).)*\}"#).unwrap();

    // API Gateway patterns
    static ref API_GATEWAY_NO_AUTH: Regex = Regex::new(r#"(?i)security\s*=\s*\[\s*\]"#).unwrap();
}

// ============================================================================
// Rule Implementations
// ============================================================================

macro_rules! impl_gcp_rule {
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
            fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Gcp] }
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

// Storage Rules
impl_gcp_rule!(GcpStorageUniformAccessRule, "GCP_GCS_001", "GCS Uniform Bucket Access Disabled",
    "Cloud Storage bucket has uniform bucket-level access disabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set uniform_bucket_level_access = true",
    "https://cloud.google.com/storage/docs/uniform-bucket-level-access",
    GCS_UNIFORM_ACCESS_DISABLED, IacResourceType::GcpStorageBucket,
    "Uniform bucket-level access is disabled");

impl_gcp_rule!(GcpStoragePublicAccessRule, "GCP_GCS_002", "GCS Bucket Public Access",
    "Cloud Storage bucket allows public access via allUsers or allAuthenticatedUsers",
    IacSeverity::Critical, IacFindingCategory::PublicStorage,
    "Remove allUsers and allAuthenticatedUsers from bucket IAM bindings",
    "https://cloud.google.com/storage/docs/access-control/making-data-public",
    GCS_PUBLIC_ACCESS, IacResourceType::GcpStorageBucket,
    "Storage bucket allows public access");

impl_gcp_rule!(GcpStorageVersioningRule, "GCP_GCS_003", "GCS Versioning Disabled",
    "Cloud Storage bucket versioning is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set versioning { enabled = true }",
    "https://cloud.google.com/storage/docs/object-versioning",
    GCS_NO_VERSIONING, IacResourceType::GcpStorageBucket,
    "Storage bucket versioning is disabled");

impl_gcp_rule!(GcpStoragePublicPreventionRule, "GCP_GCS_004", "GCS Public Access Prevention Unspecified",
    "Cloud Storage bucket public access prevention is not enforced",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set public_access_prevention = 'enforced'",
    "https://cloud.google.com/storage/docs/public-access-prevention",
    GCS_PUBLIC_PREVENTION_UNSPECIFIED, IacResourceType::GcpStorageBucket,
    "Public access prevention is not enforced");

// Compute Rules
impl_gcp_rule!(GcpComputePublicIpRule, "GCP_GCE_001", "GCE Instance with Public IP",
    "Compute Engine instance has external IP address via access_config",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Remove access_config block and use Cloud NAT for outbound access",
    "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
    COMPUTE_PUBLIC_IP, IacResourceType::GcpComputeInstance,
    "Compute instance has public IP");

impl_gcp_rule!(GcpComputeDefaultSaRule, "GCP_GCE_002", "GCE Using Default Service Account",
    "Compute Engine instance uses default compute service account",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Create and use a dedicated service account with minimal permissions",
    "https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances",
    COMPUTE_DEFAULT_SA, IacResourceType::GcpComputeInstance,
    "Instance using default service account");

impl_gcp_rule!(GcpComputeVtpmDisabledRule, "GCP_GCE_003", "GCE vTPM Disabled",
    "Compute Engine instance has vTPM disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set enable_vtpm = true in shielded_instance_config",
    "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
    COMPUTE_VTPM_DISABLED, IacResourceType::GcpComputeInstance,
    "vTPM is disabled");

impl_gcp_rule!(GcpComputeIntegrityDisabledRule, "GCP_GCE_004", "GCE Integrity Monitoring Disabled",
    "Compute Engine instance integrity monitoring is disabled",
    IacSeverity::Medium, IacFindingCategory::MissingLogging,
    "Set enable_integrity_monitoring = true in shielded_instance_config",
    "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm",
    COMPUTE_INTEGRITY_DISABLED, IacResourceType::GcpComputeInstance,
    "Integrity monitoring is disabled");

impl_gcp_rule!(GcpComputeSerialPortRule, "GCP_GCE_005", "GCE Serial Port Enabled",
    "Compute Engine instance has serial port access enabled",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set serial-port-enable = false in metadata",
    "https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console",
    COMPUTE_SERIAL_PORT_ENABLED, IacResourceType::GcpComputeInstance,
    "Serial port access is enabled");

impl_gcp_rule!(GcpComputeProjectSshKeysRule, "GCP_GCE_006", "GCE Project SSH Keys Not Blocked",
    "Compute Engine instance does not block project-wide SSH keys",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set block_project_ssh_keys = true in metadata",
    "https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys",
    COMPUTE_PROJECT_SSH_KEYS, IacResourceType::GcpComputeInstance,
    "Project-wide SSH keys not blocked");

impl_gcp_rule!(GcpComputeOsLoginDisabledRule, "GCP_GCE_007", "GCE OS Login Disabled",
    "Compute Engine instance has OS Login disabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set enable-oslogin = TRUE in metadata",
    "https://cloud.google.com/compute/docs/oslogin",
    COMPUTE_OS_LOGIN_DISABLED, IacResourceType::GcpComputeInstance,
    "OS Login is disabled");

impl_gcp_rule!(GcpComputeIpForwardingRule, "GCP_GCE_008", "GCE IP Forwarding Enabled",
    "Compute Engine instance has IP forwarding enabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set can_ip_forward = false unless required for NAT/routing",
    "https://cloud.google.com/compute/docs/instances/create-start-instance",
    COMPUTE_IP_FORWARDING, IacResourceType::GcpComputeInstance,
    "IP forwarding is enabled");

// Network Rules
impl_gcp_rule!(GcpFirewallAllOpenRule, "GCP_FW_001", "Firewall Allows All Traffic from Internet",
    "Firewall rule allows all traffic from 0.0.0.0/0",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Restrict source_ranges to specific IP ranges and limit protocol/ports",
    "https://cloud.google.com/vpc/docs/firewalls",
    FIREWALL_ALL_OPEN, IacResourceType::GcpFirewallRule,
    "Firewall allows all traffic from internet");

impl_gcp_rule!(GcpVpcLegacyNetworkRule, "GCP_VPC_001", "VPC Legacy Network Mode",
    "VPC uses legacy auto mode with overlapping subnets",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set auto_create_subnetworks = false and create custom subnets",
    "https://cloud.google.com/vpc/docs/vpc#auto-mode-considerations",
    VPC_LEGACY_NETWORK, IacResourceType::GcpVpcNetwork,
    "VPC using auto mode (legacy)");

impl_gcp_rule!(GcpVpcPrivateAccessRule, "GCP_VPC_002", "VPC Private Google Access Disabled",
    "Subnet has Private Google Access disabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set private_ip_google_access = true",
    "https://cloud.google.com/vpc/docs/configure-private-google-access",
    VPC_PRIVATE_ACCESS_DISABLED, IacResourceType::GcpSubnetwork,
    "Private Google Access is disabled");

// IAM Rules
impl_gcp_rule!(GcpIamPublicBindingRule, "GCP_IAM_001", "IAM Binding with allUsers",
    "IAM binding grants access to allUsers (public)",
    IacSeverity::Critical, IacFindingCategory::IamMisconfiguration,
    "Remove allUsers from IAM bindings and use specific principals",
    "https://cloud.google.com/iam/docs/overview",
    IAM_BINDING_PUBLIC, IacResourceType::GcpIamBinding,
    "IAM binding grants access to allUsers");

impl_gcp_rule!(GcpIamAuthUsersBindingRule, "GCP_IAM_002", "IAM Binding with allAuthenticatedUsers",
    "IAM binding grants access to allAuthenticatedUsers",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Remove allAuthenticatedUsers and use specific principals",
    "https://cloud.google.com/iam/docs/overview",
    IAM_BINDING_AUTH_USERS, IacResourceType::GcpIamBinding,
    "IAM binding grants access to allAuthenticatedUsers");

impl_gcp_rule!(GcpIamPrimitiveRolesRule, "GCP_IAM_003", "IAM Primitive Role Used",
    "IAM binding uses primitive role (owner/editor/viewer)",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Use predefined or custom roles instead of primitive roles",
    "https://cloud.google.com/iam/docs/understanding-roles#primitive_roles",
    IAM_PRIMITIVE_ROLES, IacResourceType::GcpIamBinding,
    "Primitive role used instead of predefined role");

impl_gcp_rule!(GcpIamSaKeyCreatedRule, "GCP_IAM_004", "Service Account Key Created",
    "Service account key is being created (prefer workload identity)",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Use Workload Identity or short-lived tokens instead of keys",
    "https://cloud.google.com/iam/docs/best-practices-for-securing-service-accounts",
    IAM_SA_KEY_CREATED, IacResourceType::GcpServiceAccount,
    "Service account key being created");

impl_gcp_rule!(GcpIamSaAdminRoleRule, "GCP_IAM_005", "Service Account Admin Role Granted",
    "Service Account Admin role is being granted",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Use more specific roles instead of broad admin access",
    "https://cloud.google.com/iam/docs/understanding-roles",
    IAM_SA_ADMIN_ROLE, IacResourceType::GcpIamBinding,
    "Service Account Admin role granted");

// GKE Rules
impl_gcp_rule!(GcpGkeLegacyAbacRule, "GCP_GKE_001", "GKE Legacy ABAC Enabled",
    "GKE cluster has legacy ABAC authorization enabled",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Set enable_legacy_abac = false and use RBAC",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control",
    GKE_LEGACY_ABAC, IacResourceType::GcpGke,
    "Legacy ABAC is enabled");

impl_gcp_rule!(GcpGkeBasicAuthRule, "GCP_GKE_002", "GKE Basic Authentication Enabled",
    "GKE cluster has basic authentication enabled",
    IacSeverity::Critical, IacFindingCategory::IamMisconfiguration,
    "Remove username from master_auth block to disable basic auth",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster",
    GKE_BASIC_AUTH, IacResourceType::GcpGke,
    "Basic authentication is enabled");

impl_gcp_rule!(GcpGkeClientCertRule, "GCP_GKE_003", "GKE Client Certificate Enabled",
    "GKE cluster has client certificate authentication enabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set issue_client_certificate = false",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster",
    GKE_CLIENT_CERT, IacResourceType::GcpGke,
    "Client certificate authentication is enabled");

impl_gcp_rule!(GcpGkeNoPrivateClusterRule, "GCP_GKE_004", "GKE Not Private Cluster",
    "GKE cluster is not configured as private cluster",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set enable_private_nodes = true in private_cluster_config",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
    GKE_NO_PRIVATE_CLUSTER, IacResourceType::GcpGke,
    "GKE is not a private cluster");

impl_gcp_rule!(GcpGkePublicEndpointRule, "GCP_GKE_005", "GKE Public Endpoint Enabled",
    "GKE cluster master has public endpoint enabled",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set enable_private_endpoint = true in private_cluster_config",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters",
    GKE_PUBLIC_ENDPOINT, IacResourceType::GcpGke,
    "GKE has public master endpoint");

impl_gcp_rule!(GcpGkeNetworkPolicyRule, "GCP_GKE_006", "GKE Network Policy Disabled",
    "GKE cluster has network policy disabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set enabled = true in network_policy block",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy",
    GKE_NO_NETWORK_POLICY, IacResourceType::GcpGke,
    "Network policy is disabled");

impl_gcp_rule!(GcpGkeShieldedNodesRule, "GCP_GKE_007", "GKE Shielded Nodes Disabled",
    "GKE cluster has shielded nodes disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set enable_shielded_nodes = true",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes",
    GKE_NO_SHIELDED_NODES, IacResourceType::GcpGke,
    "Shielded nodes are disabled");

impl_gcp_rule!(GcpGkeBinaryAuthRule, "GCP_GKE_008", "GKE Binary Authorization Disabled",
    "GKE cluster has binary authorization disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set enable_binary_authorization = true",
    "https://cloud.google.com/binary-authorization/docs/overview",
    GKE_NO_BINARY_AUTH, IacResourceType::GcpGke,
    "Binary authorization is disabled");

impl_gcp_rule!(GcpGkeReleaseChannelRule, "GCP_GKE_009", "GKE Release Channel Unspecified",
    "GKE cluster is not subscribed to a release channel",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set channel = 'REGULAR' or 'STABLE' in release_channel block",
    "https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels",
    GKE_RELEASE_CHANNEL_UNSPECIFIED, IacResourceType::GcpGke,
    "Release channel is unspecified");

impl_gcp_rule!(GcpGkeIntranodeVisibilityRule, "GCP_GKE_010", "GKE Intranode Visibility Disabled",
    "GKE cluster intranode visibility is disabled",
    IacSeverity::Low, IacFindingCategory::MissingLogging,
    "Set enable_intranode_visibility = true",
    "https://cloud.google.com/kubernetes-engine/docs/how-to/intranode-visibility",
    GKE_INTRANODE_VISIBILITY_DISABLED, IacResourceType::GcpGke,
    "Intranode visibility is disabled");

// Cloud SQL Rules
impl_gcp_rule!(GcpSqlPublicIpRule, "GCP_SQL_001", "Cloud SQL Public IP Enabled",
    "Cloud SQL instance has public IP enabled",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set ipv4_enabled = false and use private IP",
    "https://cloud.google.com/sql/docs/mysql/configure-private-ip",
    SQL_PUBLIC_IP, IacResourceType::GcpCloudSql,
    "Cloud SQL has public IP enabled");

impl_gcp_rule!(GcpSqlNoSslRule, "GCP_SQL_002", "Cloud SQL SSL Not Required",
    "Cloud SQL instance does not require SSL connections",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set require_ssl = true in ip_configuration",
    "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
    SQL_NO_SSL, IacResourceType::GcpCloudSql,
    "SSL is not required for connections");

impl_gcp_rule!(GcpSqlNoBackupRule, "GCP_SQL_003", "Cloud SQL Backup Disabled",
    "Cloud SQL instance automated backups are disabled",
    IacSeverity::High, IacFindingCategory::DataProtection,
    "Set enabled = true in backup_configuration",
    "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
    SQL_NO_BACKUP, IacResourceType::GcpCloudSql,
    "Automated backups are disabled");

impl_gcp_rule!(GcpSqlPitrDisabledRule, "GCP_SQL_004", "Cloud SQL PITR Disabled",
    "Cloud SQL instance point-in-time recovery is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set point_in_time_recovery_enabled = true in backup_configuration",
    "https://cloud.google.com/sql/docs/mysql/backup-recovery/pitr",
    SQL_PITR_DISABLED, IacResourceType::GcpCloudSql,
    "Point-in-time recovery is disabled");

impl_gcp_rule!(GcpSqlAuthorizedNetworksOpenRule, "GCP_SQL_005", "Cloud SQL Open to Internet",
    "Cloud SQL instance allows connections from 0.0.0.0/0",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Restrict authorized_networks to specific IP ranges",
    "https://cloud.google.com/sql/docs/mysql/configure-ip",
    SQL_AUTHORIZED_NETWORKS_OPEN, IacResourceType::GcpCloudSql,
    "Cloud SQL allows connections from anywhere");

impl_gcp_rule!(GcpSqlLocalInfileRule, "GCP_SQL_006", "Cloud SQL Local Infile Enabled",
    "Cloud SQL instance has local_infile flag enabled",
    IacSeverity::High, IacFindingCategory::DataProtection,
    "Remove local_infile database flag or set to 'off'",
    "https://cloud.google.com/sql/docs/mysql/flags",
    SQL_LOCAL_FLAGS_ENABLED, IacResourceType::GcpCloudSql,
    "local_infile flag is enabled");

// BigQuery Rules
impl_gcp_rule!(GcpBqPublicAccessRule, "GCP_BQ_001", "BigQuery Dataset Public Access",
    "BigQuery dataset allows access from allAuthenticatedUsers",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Remove allAuthenticatedUsers from dataset access block",
    "https://cloud.google.com/bigquery/docs/dataset-access-controls",
    BQ_PUBLIC_ACCESS, IacResourceType::GcpBigQuery,
    "BigQuery dataset allows public access");

// Cloud Functions Rules
impl_gcp_rule!(GcpFunctionPublicInvokerRule, "GCP_CF_001", "Cloud Function Public Invoker",
    "Cloud Function allows invocation by allUsers",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Remove allUsers from invoker role and use authenticated access",
    "https://cloud.google.com/functions/docs/securing/managing-access-iam",
    FUNCTION_PUBLIC_INVOKER, IacResourceType::GcpCloudFunction,
    "Cloud Function allows public invocation");

impl_gcp_rule!(GcpFunctionIngressAllRule, "GCP_CF_002", "Cloud Function Allows All Ingress",
    "Cloud Function allows ingress from all sources",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set ingress_settings = 'ALLOW_INTERNAL_ONLY' or 'ALLOW_INTERNAL_AND_GCLB'",
    "https://cloud.google.com/functions/docs/networking/network-settings",
    FUNCTION_INGRESS_ALL, IacResourceType::GcpCloudFunction,
    "Cloud Function allows all ingress");

// Cloud Run Rules
impl_gcp_rule!(GcpRunPublicInvokerRule, "GCP_CR_001", "Cloud Run Public Invoker",
    "Cloud Run service allows invocation by allUsers",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Remove allUsers from invoker role and use authenticated access",
    "https://cloud.google.com/run/docs/authenticating/public",
    RUN_PUBLIC_INVOKER, IacResourceType::GcpCloudRun,
    "Cloud Run allows public invocation");

impl_gcp_rule!(GcpRunIngressAllRule, "GCP_CR_002", "Cloud Run Allows All Ingress",
    "Cloud Run service allows ingress from all sources",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set ingress = 'internal' or 'internal-and-cloud-load-balancing'",
    "https://cloud.google.com/run/docs/securing/ingress",
    RUN_INGRESS_ALL, IacResourceType::GcpCloudRun,
    "Cloud Run allows all ingress");

// KMS Rules
impl_gcp_rule!(GcpKmsPublicKeyRule, "GCP_KMS_001", "KMS Key Public Access",
    "KMS key grants access to allUsers",
    IacSeverity::Critical, IacFindingCategory::IamMisconfiguration,
    "Remove allUsers from KMS key IAM bindings",
    "https://cloud.google.com/kms/docs/iam",
    KMS_PUBLIC_KEY, IacResourceType::GcpKmsKey,
    "KMS key allows public access");

impl_gcp_rule!(GcpKmsNoRotationRule, "GCP_KMS_002", "KMS Key No Rotation",
    "KMS key does not have automatic rotation configured",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set rotation_period in google_kms_crypto_key resource",
    "https://cloud.google.com/kms/docs/key-rotation",
    KMS_NO_ROTATION, IacResourceType::GcpKmsKey,
    "KMS key rotation is not configured");

// Dataproc Rules
impl_gcp_rule!(GcpDataprocPublicIpRule, "GCP_DP_001", "Dataproc Cluster Public IP",
    "Dataproc cluster uses external IP addresses",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set internal_ip_only = true in gce_cluster_config",
    "https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/network",
    DATAPROC_PUBLIC_IP, IacResourceType::GcpDataproc,
    "Dataproc cluster has public IPs");

// Secret Manager Rules
impl_gcp_rule!(GcpSecretNoRotationRule, "GCP_SM_001", "Secret Manager No Rotation",
    "Secret Manager secret does not have rotation configured",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Configure rotation block in google_secret_manager_secret resource",
    "https://cloud.google.com/secret-manager/docs/rotation",
    SECRET_NO_ROTATION, IacResourceType::GcpSecretManager,
    "Secret rotation is not configured");

/// Get all GCP rules
pub fn get_gcp_rules() -> Vec<Box<dyn RuleMatcher>> {
    vec![
        // Storage Rules
        Box::new(GcpStorageUniformAccessRule),
        Box::new(GcpStoragePublicAccessRule),
        Box::new(GcpStorageVersioningRule),
        Box::new(GcpStoragePublicPreventionRule),
        // Compute Rules
        Box::new(GcpComputePublicIpRule),
        Box::new(GcpComputeDefaultSaRule),
        Box::new(GcpComputeVtpmDisabledRule),
        Box::new(GcpComputeIntegrityDisabledRule),
        Box::new(GcpComputeSerialPortRule),
        Box::new(GcpComputeProjectSshKeysRule),
        Box::new(GcpComputeOsLoginDisabledRule),
        Box::new(GcpComputeIpForwardingRule),
        // Network Rules
        Box::new(GcpFirewallAllOpenRule),
        Box::new(GcpVpcLegacyNetworkRule),
        Box::new(GcpVpcPrivateAccessRule),
        // IAM Rules
        Box::new(GcpIamPublicBindingRule),
        Box::new(GcpIamAuthUsersBindingRule),
        Box::new(GcpIamPrimitiveRolesRule),
        Box::new(GcpIamSaKeyCreatedRule),
        Box::new(GcpIamSaAdminRoleRule),
        // GKE Rules
        Box::new(GcpGkeLegacyAbacRule),
        Box::new(GcpGkeBasicAuthRule),
        Box::new(GcpGkeClientCertRule),
        Box::new(GcpGkeNoPrivateClusterRule),
        Box::new(GcpGkePublicEndpointRule),
        Box::new(GcpGkeNetworkPolicyRule),
        Box::new(GcpGkeShieldedNodesRule),
        Box::new(GcpGkeBinaryAuthRule),
        Box::new(GcpGkeReleaseChannelRule),
        Box::new(GcpGkeIntranodeVisibilityRule),
        // Cloud SQL Rules
        Box::new(GcpSqlPublicIpRule),
        Box::new(GcpSqlNoSslRule),
        Box::new(GcpSqlNoBackupRule),
        Box::new(GcpSqlPitrDisabledRule),
        Box::new(GcpSqlAuthorizedNetworksOpenRule),
        Box::new(GcpSqlLocalInfileRule),
        // BigQuery Rules
        Box::new(GcpBqPublicAccessRule),
        // Cloud Functions Rules
        Box::new(GcpFunctionPublicInvokerRule),
        Box::new(GcpFunctionIngressAllRule),
        // Cloud Run Rules
        Box::new(GcpRunPublicInvokerRule),
        Box::new(GcpRunIngressAllRule),
        // KMS Rules
        Box::new(GcpKmsPublicKeyRule),
        Box::new(GcpKmsNoRotationRule),
        // Dataproc Rules
        Box::new(GcpDataprocPublicIpRule),
        // Secret Manager Rules
        Box::new(GcpSecretNoRotationRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcp_rules_count() {
        let rules = get_gcp_rules();
        assert!(rules.len() >= 40, "Expected at least 40 GCP rules, got {}", rules.len());
    }

    #[test]
    fn test_gcs_public_access_detection() {
        let rule = GcpStoragePublicAccessRule;
        let content = r#"
resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_gke_private_cluster_detection() {
        let rule = GcpGkeNoPrivateClusterRule;
        let content = r#"
resource "google_container_cluster" "example" {
  name = "example"
  private_cluster_config {
    enable_private_nodes = false
  }
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }
}
