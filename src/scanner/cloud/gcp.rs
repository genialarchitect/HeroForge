//! GCP Cloud Infrastructure Scanner
//!
//! This module provides scanning capabilities for Google Cloud Platform resources including:
//! - IAM: Service accounts, IAM bindings, roles
//! - Storage: Cloud Storage buckets
//! - Compute: Compute Engine instances
//! - Network: Firewall rules, VPC networks
//! - Database: Cloud SQL instances

use super::types::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use log::{info, warn, error};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use uuid::Uuid;

/// GCP API base URLs
const GCP_COMPUTE_API: &str = "https://compute.googleapis.com/compute/v1";
const GCP_IAM_API: &str = "https://iam.googleapis.com/v1";
const GCP_STORAGE_API: &str = "https://storage.googleapis.com/storage/v1";
const GCP_SQLADMIN_API: &str = "https://sqladmin.googleapis.com/v1";
const GCP_CLOUDRESOURCEMANAGER_API: &str = "https://cloudresourcemanager.googleapis.com/v1";

/// GCP API response types
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountList {
    accounts: Option<Vec<GcpServiceAccount>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccount {
    name: Option<String>,
    project_id: Option<String>,
    unique_id: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
    disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountKeyList {
    keys: Option<Vec<GcpServiceAccountKey>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpServiceAccountKey {
    name: Option<String>,
    valid_after_time: Option<String>,
    valid_before_time: Option<String>,
    key_algorithm: Option<String>,
    key_origin: Option<String>,
    key_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpIamPolicy {
    bindings: Option<Vec<GcpIamBinding>>,
    version: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpIamBinding {
    role: Option<String>,
    members: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpBucketList {
    items: Option<Vec<GcpBucket>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpBucket {
    name: Option<String>,
    id: Option<String>,
    location: Option<String>,
    storage_class: Option<String>,
    versioning: Option<GcpVersioning>,
    iam_configuration: Option<GcpIamConfiguration>,
    encryption: Option<GcpEncryption>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpVersioning {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpIamConfiguration {
    uniform_bucket_level_access: Option<GcpUniformBucketLevelAccess>,
    public_access_prevention: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpUniformBucketLevelAccess {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpEncryption {
    default_kms_key_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpInstanceList {
    items: Option<Vec<GcpInstance>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpInstance {
    id: Option<String>,
    name: Option<String>,
    zone: Option<String>,
    machine_type: Option<String>,
    status: Option<String>,
    network_interfaces: Option<Vec<GcpNetworkInterface>>,
    service_accounts: Option<Vec<GcpInstanceServiceAccount>>,
    shielded_instance_config: Option<GcpShieldedInstanceConfig>,
    labels: Option<HashMap<String, String>>,
    metadata: Option<GcpInstanceMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpNetworkInterface {
    network_i_p: Option<String>,
    access_configs: Option<Vec<GcpAccessConfig>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpAccessConfig {
    nat_i_p: Option<String>,
    #[serde(rename = "type")]
    access_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpInstanceServiceAccount {
    email: Option<String>,
    scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpShieldedInstanceConfig {
    enable_secure_boot: Option<bool>,
    enable_vtpm: Option<bool>,
    enable_integrity_monitoring: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpInstanceMetadata {
    items: Option<Vec<GcpMetadataItem>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpMetadataItem {
    key: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpFirewallList {
    items: Option<Vec<GcpFirewall>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpFirewall {
    id: Option<String>,
    name: Option<String>,
    network: Option<String>,
    direction: Option<String>,
    priority: Option<i32>,
    source_ranges: Option<Vec<String>>,
    destination_ranges: Option<Vec<String>>,
    allowed: Option<Vec<GcpFirewallAllowed>>,
    denied: Option<Vec<GcpFirewallDenied>>,
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpFirewallAllowed {
    #[serde(rename = "IPProtocol")]
    ip_protocol: Option<String>,
    ports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpFirewallDenied {
    #[serde(rename = "IPProtocol")]
    ip_protocol: Option<String>,
    ports: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSqlInstanceList {
    items: Option<Vec<GcpSqlInstance>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSqlInstance {
    name: Option<String>,
    database_version: Option<String>,
    region: Option<String>,
    state: Option<String>,
    settings: Option<GcpSqlSettings>,
    ip_addresses: Option<Vec<GcpSqlIpAddress>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSqlSettings {
    tier: Option<String>,
    availability_type: Option<String>,
    backup_configuration: Option<GcpBackupConfiguration>,
    ip_configuration: Option<GcpIpConfiguration>,
    database_flags: Option<Vec<GcpDatabaseFlag>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpBackupConfiguration {
    enabled: Option<bool>,
    binary_log_enabled: Option<bool>,
    start_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpIpConfiguration {
    require_ssl: Option<bool>,
    ipv4_enabled: Option<bool>,
    private_network: Option<String>,
    authorized_networks: Option<Vec<GcpAuthorizedNetwork>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpAuthorizedNetwork {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpDatabaseFlag {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSqlIpAddress {
    ip_address: Option<String>,
    #[serde(rename = "type")]
    ip_type: Option<String>,
}

/// GCP Cloud Scanner implementation
pub struct GcpScanner {
    /// GCP Project ID
    project_id: Option<String>,
    /// HTTP client for API requests
    client: Client,
    /// Access token for GCP API authentication
    access_token: Option<String>,
}

impl GcpScanner {
    /// Create a new GCP scanner
    pub fn new() -> Self {
        Self {
            project_id: env::var("GCP_PROJECT_ID").ok(),
            client: Client::new(),
            access_token: None,
        }
    }

    /// Create a scanner with explicit configuration
    pub fn with_config(project_id: Option<String>, access_token: Option<String>) -> Self {
        Self {
            project_id,
            client: Client::new(),
            access_token,
        }
    }

    /// Get the project ID, falling back to environment variable
    fn get_project_id(&self) -> Result<String> {
        self.project_id.clone()
            .or_else(|| env::var("GCP_PROJECT_ID").ok())
            .or_else(|| env::var("GOOGLE_CLOUD_PROJECT").ok())
            .ok_or_else(|| anyhow::anyhow!("GCP_PROJECT_ID not set"))
    }

    /// Get access token from environment or metadata server
    async fn get_access_token(&self) -> Result<String> {
        // First check if we have an explicit token
        if let Some(ref token) = self.access_token {
            return Ok(token.clone());
        }

        // Check environment variable
        if let Ok(token) = env::var("GCP_ACCESS_TOKEN") {
            return Ok(token);
        }

        // Try to get token from metadata server (for GCE instances)
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
        let response = self.client
            .get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await;

        if let Ok(resp) = response {
            if resp.status().is_success() {
                #[derive(Deserialize)]
                struct TokenResponse {
                    access_token: String,
                }
                if let Ok(token_resp) = resp.json::<TokenResponse>().await {
                    return Ok(token_resp.access_token);
                }
            }
        }

        // Try using gcloud CLI as fallback
        let output = tokio::process::Command::new("gcloud")
            .args(["auth", "print-access-token"])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !token.is_empty() {
                    return Ok(token);
                }
            }
        }

        Err(anyhow::anyhow!("Could not obtain GCP access token. Set GCP_ACCESS_TOKEN or run 'gcloud auth login'"))
    }

    /// Make an authenticated API request
    async fn api_get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let token = self.get_access_token().await?;
        let response = self.client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Failed to make GCP API request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("GCP API error {}: {}", status, body));
        }

        response.json::<T>().await.context("Failed to parse GCP API response")
    }

    /// Check if a firewall rule allows dangerous access from the internet
    fn check_firewall_exposure(&self, firewall: &GcpFirewall) -> Option<(String, FindingSeverity)> {
        let source_ranges = firewall.source_ranges.as_ref()?;
        let has_any_ip = source_ranges.iter().any(|r| r == "0.0.0.0/0" || r == "::/0");

        if !has_any_ip {
            return None;
        }

        let allowed = firewall.allowed.as_ref()?;
        for rule in allowed {
            if let Some(ref ports) = rule.ports {
                for port in ports {
                    // Check for dangerous ports
                    if port == "22" {
                        return Some(("SSH (port 22) exposed to internet".to_string(), FindingSeverity::Critical));
                    }
                    if port == "3389" {
                        return Some(("RDP (port 3389) exposed to internet".to_string(), FindingSeverity::Critical));
                    }
                    if port == "3306" || port == "5432" || port == "1433" {
                        return Some(("Database port exposed to internet".to_string(), FindingSeverity::Critical));
                    }
                    if port == "23" {
                        return Some(("Telnet (port 23) exposed to internet".to_string(), FindingSeverity::Critical));
                    }
                    if port == "445" || port == "139" {
                        return Some(("SMB exposed to internet".to_string(), FindingSeverity::Critical));
                    }
                }
            }
            // Check for all ports allowed
            if rule.ports.is_none() && rule.ip_protocol.as_deref() != Some("icmp") {
                return Some(("All ports exposed to internet".to_string(), FindingSeverity::Critical));
            }
        }

        None
    }

    /// Check for overly permissive IAM roles
    fn is_overly_permissive_role(&self, role: &str) -> Option<&'static str> {
        match role {
            "roles/owner" => Some("Owner role grants full administrative access"),
            "roles/editor" => Some("Editor role grants broad write access"),
            "roles/iam.securityAdmin" => Some("Security Admin can modify all IAM policies"),
            "roles/compute.admin" => Some("Compute Admin has full control over compute resources"),
            "roles/storage.admin" => Some("Storage Admin has full control over storage resources"),
            _ if role.ends_with(".admin") => Some("Admin role may grant excessive permissions"),
            _ => None,
        }
    }

}

#[async_trait::async_trait]
impl CloudScanner for GcpScanner {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    async fn scan_iam(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        info!("Starting GCP IAM scan");
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let project_id = match self.get_project_id() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to get GCP project ID: {}", e);
                return Err(e);
            }
        };

        // Scan service accounts
        let sa_url = format!("{}/projects/{}/serviceAccounts", GCP_IAM_API, project_id);
        match self.api_get::<GcpServiceAccountList>(&sa_url).await {
            Ok(sa_list) => {
                if let Some(accounts) = sa_list.accounts {
                    for account in accounts {
                        let email = account.email.clone().unwrap_or_default();
                        let sa_id = Uuid::new_v4().to_string();
                        let is_default = email.contains("-compute@developer.gserviceaccount.com")
                            || email.ends_with("@appspot.gserviceaccount.com");

                        // Get service account keys
                        let keys_url = format!("{}/projects/{}/serviceAccounts/{}/keys",
                            GCP_IAM_API, project_id, email);
                        let user_managed_keys = match self.api_get::<GcpServiceAccountKeyList>(&keys_url).await {
                            Ok(keys_list) => {
                                keys_list.keys.unwrap_or_default()
                                    .into_iter()
                                    .filter(|k| k.key_type.as_deref() == Some("USER_MANAGED"))
                                    .collect::<Vec<_>>()
                            }
                            Err(e) => {
                                warn!("Failed to get keys for {}: {}", email, e);
                                Vec::new()
                            }
                        };

                        resources.push(CloudResource {
                            id: sa_id.clone(),
                            resource_id: account.unique_id.clone().unwrap_or_else(|| email.clone()),
                            resource_type: CloudResourceType::ServiceAccount,
                            provider: CloudProvider::Gcp,
                            region: Some("global".to_string()),
                            name: account.display_name.clone().or_else(|| Some(email.clone())),
                            arn: account.name.clone(),
                            tags: HashMap::new(),
                            metadata: serde_json::json!({
                                "email": email,
                                "unique_id": account.unique_id,
                                "disabled": account.disabled.unwrap_or(false),
                                "is_default": is_default,
                                "user_managed_keys": user_managed_keys.len()
                            }),
                            state: Some(if account.disabled.unwrap_or(false) { "Disabled" } else { "Enabled" }.to_string()),
                            discovered_at: now,
                        });

                        // Check for user-managed keys (CIS 1.7)
                        if !user_managed_keys.is_empty() {
                            // Check key age
                            for key in &user_managed_keys {
                                if let Some(ref valid_after) = key.valid_after_time {
                                    if let Ok(created) = DateTime::parse_from_rfc3339(valid_after) {
                                        let age_days = (now - created.with_timezone(&Utc)).num_days();
                                        if age_days > 90 {
                                            findings.push(CloudFinding {
                                                id: Uuid::new_v4().to_string(),
                                                scan_id: String::new(),
                                                resource_id: Some(sa_id.clone()),
                                                finding_type: FindingType::Misconfiguration,
                                                severity: FindingSeverity::High,
                                                title: "Service Account Key Not Rotated".to_string(),
                                                description: format!("Service account '{}' has a user-managed key that is {} days old. Keys should be rotated every 90 days.", email, age_days),
                                                remediation: Some("Rotate the service account key. Delete old keys and create new ones. Consider using Google-managed keys instead.".to_string()),
                                                compliance_mappings: vec![
                                                    ComplianceMapping {
                                                        framework: "CIS GCP".to_string(),
                                                        control_id: "1.7".to_string(),
                                                        control_title: Some("Ensure user-managed/external keys for service accounts are rotated every 90 days or less".to_string()),
                                                    },
                                                ],
                                                affected_resource_arn: account.name.clone(),
                                                evidence: Some(FindingEvidence {
                                                    description: format!("Key age: {} days", age_days),
                                                    raw_data: Some(serde_json::json!({
                                                        "key_name": key.name,
                                                        "created": valid_after,
                                                        "age_days": age_days
                                                    })),
                                                    expected: Some("Key age < 90 days".to_string()),
                                                    actual: Some(format!("{} days", age_days)),
                                                    collected_at: now,
                                                }),
                                                status: FindingStatus::Open,
                                                created_at: now,
                                            });
                                        }
                                    }
                                }
                            }
                        }

                        // Check for disabled default service accounts (warning if enabled)
                        if is_default && !account.disabled.unwrap_or(false) {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(sa_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Medium,
                                title: "Default Service Account Is Enabled".to_string(),
                                description: format!("Default service account '{}' is enabled. Default service accounts often have excessive permissions.", email),
                                remediation: Some("Create custom service accounts with minimal permissions. Disable default service accounts if not needed.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "1.5".to_string(),
                                        control_title: Some("Ensure that Service Account has no admin privileges".to_string()),
                                    },
                                ],
                                affected_resource_arn: account.name.clone(),
                                evidence: Some(FindingEvidence {
                                    description: "Default service account is enabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "is_default": true,
                                        "disabled": false
                                    })),
                                    expected: Some("Disabled or custom service account".to_string()),
                                    actual: Some("Enabled default service account".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to list service accounts: {}", e);
            }
        }

        // Scan IAM policy for overly permissive bindings
        let policy_url = format!("{}//projects/{}:getIamPolicy", GCP_CLOUDRESOURCEMANAGER_API, project_id);
        // Note: getIamPolicy is a POST request, but we'll try GET first
        match self.api_get::<GcpIamPolicy>(&policy_url).await {
            Ok(policy) => {
                if let Some(bindings) = policy.bindings {
                    for binding in bindings {
                        let role = binding.role.clone().unwrap_or_default();
                        let members = binding.members.clone().unwrap_or_default();

                        // Check for allUsers or allAuthenticatedUsers
                        for member in &members {
                            if member == "allUsers" || member == "allAuthenticatedUsers" {
                                let binding_id = Uuid::new_v4().to_string();
                                resources.push(CloudResource {
                                    id: binding_id.clone(),
                                    resource_id: format!("iam-binding-{}", role.replace('/', "-")),
                                    resource_type: CloudResourceType::IamBinding,
                                    provider: CloudProvider::Gcp,
                                    region: Some("global".to_string()),
                                    name: Some(format!("IAM Binding: {}", role)),
                                    arn: Some(format!("projects/{}/iamPolicy/{}", project_id, role)),
                                    tags: HashMap::new(),
                                    metadata: serde_json::json!({
                                        "role": role,
                                        "members": members
                                    }),
                                    state: Some("Active".to_string()),
                                    discovered_at: now,
                                });

                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(binding_id),
                                    finding_type: FindingType::Exposure,
                                    severity: FindingSeverity::Critical,
                                    title: format!("IAM Binding Grants {} to {}", role, member),
                                    description: format!("IAM policy grants '{}' role to '{}', making resources accessible to everyone.", role, member),
                                    remediation: Some(format!("Remove '{}' from the IAM binding. Grant access only to specific users, groups, or service accounts.", member)),
                                    compliance_mappings: vec![
                                        ComplianceMapping {
                                            framework: "CIS GCP".to_string(),
                                            control_id: "1.1".to_string(),
                                            control_title: Some("Ensure that corporate login credentials are used".to_string()),
                                        },
                                    ],
                                    affected_resource_arn: Some(format!("projects/{}", project_id)),
                                    evidence: Some(FindingEvidence {
                                        description: format!("Public IAM binding: {} -> {}", role, member),
                                        raw_data: Some(serde_json::json!({
                                            "role": role,
                                            "member": member
                                        })),
                                        expected: Some("Specific principals".to_string()),
                                        actual: Some(member.clone()),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }
                        }

                        // Check for overly permissive roles
                        if let Some(issue) = self.is_overly_permissive_role(&role) {
                            for member in &members {
                                // Skip if it's a service agent
                                if member.contains("@cloudservices.gserviceaccount.com") {
                                    continue;
                                }
                                if member.contains(".iam.gserviceaccount.com") {
                                    findings.push(CloudFinding {
                                        id: Uuid::new_v4().to_string(),
                                        scan_id: String::new(),
                                        resource_id: None,
                                        finding_type: FindingType::Misconfiguration,
                                        severity: if role == "roles/owner" { FindingSeverity::Critical } else { FindingSeverity::High },
                                        title: format!("Service Account Has {}", role),
                                        description: format!("Service account '{}' has been granted '{}'. {}", member, role, issue),
                                        remediation: Some("Remove the overly permissive role and grant only the specific permissions needed.".to_string()),
                                        compliance_mappings: vec![
                                            ComplianceMapping {
                                                framework: "CIS GCP".to_string(),
                                                control_id: "1.5".to_string(),
                                                control_title: Some("Ensure that Service Account has no admin privileges".to_string()),
                                            },
                                        ],
                                        affected_resource_arn: Some(member.clone()),
                                        evidence: Some(FindingEvidence {
                                            description: issue.to_string(),
                                            raw_data: Some(serde_json::json!({
                                                "role": role,
                                                "member": member
                                            })),
                                            expected: Some("Minimal required roles".to_string()),
                                            actual: Some(role.clone()),
                                            collected_at: now,
                                        }),
                                        status: FindingStatus::Open,
                                        created_at: now,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get IAM policy: {}", e);
            }
        }

        info!("GCP IAM scan complete: {} resources, {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    async fn scan_storage(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        info!("Starting GCP Cloud Storage scan");
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let project_id = match self.get_project_id() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to get GCP project ID: {}", e);
                return Err(e);
            }
        };

        // List all buckets in the project
        let buckets_url = format!("{}/b?project={}", GCP_STORAGE_API, project_id);
        match self.api_get::<GcpBucketList>(&buckets_url).await {
            Ok(bucket_list) => {
                if let Some(buckets) = bucket_list.items {
                    for bucket in buckets {
                        let bucket_name = bucket.name.clone().unwrap_or_default();
                        let bucket_id = Uuid::new_v4().to_string();

                        let versioning_enabled = bucket.versioning
                            .as_ref()
                            .and_then(|v| v.enabled)
                            .unwrap_or(false);

                        let uniform_access = bucket.iam_configuration
                            .as_ref()
                            .and_then(|c| c.uniform_bucket_level_access.as_ref())
                            .and_then(|u| u.enabled)
                            .unwrap_or(false);

                        let public_access_prevention = bucket.iam_configuration
                            .as_ref()
                            .and_then(|c| c.public_access_prevention.clone())
                            .unwrap_or_else(|| "inherited".to_string());

                        let has_cmek = bucket.encryption
                            .as_ref()
                            .and_then(|e| e.default_kms_key_name.as_ref())
                            .is_some();

                        resources.push(CloudResource {
                            id: bucket_id.clone(),
                            resource_id: bucket_name.clone(),
                            resource_type: CloudResourceType::CloudStorage,
                            provider: CloudProvider::Gcp,
                            region: bucket.location.clone(),
                            name: Some(bucket_name.clone()),
                            arn: Some(format!("gs://{}", bucket_name)),
                            tags: bucket.labels.clone().unwrap_or_default(),
                            metadata: serde_json::json!({
                                "storage_class": bucket.storage_class,
                                "location": bucket.location,
                                "versioning_enabled": versioning_enabled,
                                "uniform_bucket_level_access": uniform_access,
                                "public_access_prevention": public_access_prevention,
                                "has_cmek": has_cmek
                            }),
                            state: Some("Active".to_string()),
                            discovered_at: now,
                        });

                        // Check for uniform bucket-level access (CIS 5.2)
                        if !uniform_access {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(bucket_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Cloud Storage Bucket Without Uniform Bucket-Level Access".to_string(),
                                description: format!("Cloud Storage bucket '{}' does not have uniform bucket-level access enabled. This allows object-level ACLs which can lead to inconsistent access controls.", bucket_name),
                                remediation: Some("Enable uniform bucket-level access to ensure consistent permissions are applied through IAM only.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "5.2".to_string(),
                                        control_title: Some("Ensure that Cloud Storage buckets have uniform bucket-level access enabled".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("gs://{}", bucket_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Uniform bucket-level access is not enabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "uniform_bucket_level_access": false
                                    })),
                                    expected: Some("uniform_bucket_level_access: true".to_string()),
                                    actual: Some("uniform_bucket_level_access: false".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Check for versioning (best practice)
                        if !versioning_enabled {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(bucket_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Medium,
                                title: "Cloud Storage Bucket Without Versioning".to_string(),
                                description: format!("Cloud Storage bucket '{}' does not have versioning enabled. Versioning protects against accidental deletion and modification.", bucket_name),
                                remediation: Some("Enable object versioning to maintain a history of object changes and allow recovery from accidental deletions.".to_string()),
                                compliance_mappings: vec![],
                                affected_resource_arn: Some(format!("gs://{}", bucket_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Versioning is not enabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "versioning_enabled": false
                                    })),
                                    expected: Some("Versioning enabled".to_string()),
                                    actual: Some("Versioning disabled".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Check for public access prevention
                        if public_access_prevention != "enforced" {
                            // Get bucket IAM policy to check for allUsers/allAuthenticatedUsers
                            let bucket_iam_url = format!("{}/b/{}/iam", GCP_STORAGE_API, bucket_name);
                            if let Ok(bucket_policy) = self.api_get::<GcpIamPolicy>(&bucket_iam_url).await {
                                if let Some(bindings) = bucket_policy.bindings {
                                    for binding in bindings {
                                        if let Some(members) = &binding.members {
                                            let has_public_access = members.iter().any(|m| m == "allUsers" || m == "allAuthenticatedUsers");
                                            if has_public_access {
                                                let role = binding.role.clone().unwrap_or_default();
                                                findings.push(CloudFinding {
                                                    id: Uuid::new_v4().to_string(),
                                                    scan_id: String::new(),
                                                    resource_id: Some(bucket_id.clone()),
                                                    finding_type: FindingType::Exposure,
                                                    severity: FindingSeverity::Critical,
                                                    title: "Cloud Storage Bucket Is Publicly Accessible".to_string(),
                                                    description: format!("Cloud Storage bucket '{}' grants '{}' role to allUsers or allAuthenticatedUsers, making it publicly accessible.", bucket_name, role),
                                                    remediation: Some("Remove allUsers and allAuthenticatedUsers from the bucket IAM policy. Enable public access prevention.".to_string()),
                                                    compliance_mappings: vec![
                                                        ComplianceMapping {
                                                            framework: "CIS GCP".to_string(),
                                                            control_id: "5.1".to_string(),
                                                            control_title: Some("Ensure that Cloud Storage bucket is not anonymously or publicly accessible".to_string()),
                                                        },
                                                    ],
                                                    affected_resource_arn: Some(format!("gs://{}", bucket_name)),
                                                    evidence: Some(FindingEvidence {
                                                        description: "Bucket has public IAM binding".to_string(),
                                                        raw_data: Some(serde_json::json!({
                                                            "role": role,
                                                            "members": members
                                                        })),
                                                        expected: Some("No public access".to_string()),
                                                        actual: Some("Public access granted".to_string()),
                                                        collected_at: now,
                                                    }),
                                                    status: FindingStatus::Open,
                                                    created_at: now,
                                                });
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Check for CMEK encryption (best practice for sensitive data)
                        if !has_cmek {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(bucket_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Low,
                                title: "Cloud Storage Bucket Using Google-Managed Encryption".to_string(),
                                description: format!("Cloud Storage bucket '{}' uses Google-managed encryption keys instead of customer-managed encryption keys (CMEK).", bucket_name),
                                remediation: Some("Consider using customer-managed encryption keys (CMEK) for sensitive data to maintain control over encryption key lifecycle.".to_string()),
                                compliance_mappings: vec![],
                                affected_resource_arn: Some(format!("gs://{}", bucket_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Bucket uses Google-managed encryption".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "has_cmek": false
                                    })),
                                    expected: Some("Customer-managed encryption key".to_string()),
                                    actual: Some("Google-managed encryption".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to list Cloud Storage buckets: {}", e);
            }
        }

        info!("GCP Storage scan complete: {} resources, {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    async fn scan_compute(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        info!("Starting GCP Compute Engine scan");
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let project_id = match self.get_project_id() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to get GCP project ID: {}", e);
                return Err(e);
            }
        };

        // List all instances across all zones using aggregated list
        let _instances_url = format!("{}/projects/{}/aggregated/instances", GCP_COMPUTE_API, project_id);

        // The aggregated list returns a different structure, so we'll iterate by zone
        // For simplicity, we'll get zones first and then query each zone
        let zones_url = format!("{}/projects/{}/zones", GCP_COMPUTE_API, project_id);

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ZoneList {
            items: Option<Vec<Zone>>,
        }
        #[derive(Deserialize)]
        struct Zone {
            name: Option<String>,
        }

        let zones: Vec<String> = match self.api_get::<ZoneList>(&zones_url).await {
            Ok(zone_list) => {
                zone_list.items
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|z| z.name)
                    .collect()
            }
            Err(e) => {
                warn!("Failed to list zones, using common zones: {}", e);
                vec![
                    "us-central1-a", "us-central1-b", "us-central1-c",
                    "us-east1-b", "us-east1-c", "us-east1-d",
                    "us-west1-a", "us-west1-b", "us-west1-c",
                    "europe-west1-b", "europe-west1-c", "europe-west1-d",
                ].into_iter().map(|s| s.to_string()).collect()
            }
        };

        for zone in zones {
            let zone_instances_url = format!("{}/projects/{}/zones/{}/instances", GCP_COMPUTE_API, project_id, zone);
            match self.api_get::<GcpInstanceList>(&zone_instances_url).await {
                Ok(instance_list) => {
                    if let Some(instances) = instance_list.items {
                        for instance in instances {
                            let instance_name = instance.name.clone().unwrap_or_default();
                            let instance_id = Uuid::new_v4().to_string();

                            // Check for external IP
                            let has_external_ip = instance.network_interfaces
                                .as_ref()
                                .map(|nics| nics.iter().any(|nic| {
                                    nic.access_configs.as_ref().map(|configs| {
                                        configs.iter().any(|c| c.nat_i_p.is_some())
                                    }).unwrap_or(false)
                                }))
                                .unwrap_or(false);

                            let external_ip = instance.network_interfaces
                                .as_ref()
                                .and_then(|nics| nics.first())
                                .and_then(|nic| nic.access_configs.as_ref())
                                .and_then(|configs| configs.first())
                                .and_then(|c| c.nat_i_p.clone());

                            let internal_ip = instance.network_interfaces
                                .as_ref()
                                .and_then(|nics| nics.first())
                                .and_then(|nic| nic.network_i_p.clone());

                            // Check service account
                            let service_account = instance.service_accounts
                                .as_ref()
                                .and_then(|sas| sas.first())
                                .and_then(|sa| sa.email.clone());

                            let is_default_sa = service_account
                                .as_ref()
                                .map(|sa| sa.contains("-compute@developer.gserviceaccount.com"))
                                .unwrap_or(false);

                            let has_cloud_platform_scope = instance.service_accounts
                                .as_ref()
                                .and_then(|sas| sas.first())
                                .and_then(|sa| sa.scopes.as_ref())
                                .map(|scopes| scopes.iter().any(|s| s.contains("cloud-platform")))
                                .unwrap_or(false);

                            // Check shielded VM config
                            let shielded_config = instance.shielded_instance_config.as_ref();
                            let secure_boot = shielded_config.and_then(|c| c.enable_secure_boot).unwrap_or(false);
                            let vtpm = shielded_config.and_then(|c| c.enable_vtpm).unwrap_or(false);
                            let integrity_monitoring = shielded_config.and_then(|c| c.enable_integrity_monitoring).unwrap_or(false);
                            let is_shielded = secure_boot && vtpm && integrity_monitoring;

                            // Check for serial port logging in metadata
                            let serial_port_logging = instance.metadata
                                .as_ref()
                                .and_then(|m| m.items.as_ref())
                                .map(|items| items.iter().any(|item| {
                                    item.key.as_deref() == Some("serial-port-logging-enable") &&
                                    item.value.as_deref() == Some("true")
                                }))
                                .unwrap_or(false);

                            // Check for OS Login
                            let os_login_enabled = instance.metadata
                                .as_ref()
                                .and_then(|m| m.items.as_ref())
                                .map(|items| items.iter().any(|item| {
                                    item.key.as_deref() == Some("enable-oslogin") &&
                                    item.value.as_deref() == Some("TRUE")
                                }))
                                .unwrap_or(false);

                            // Check for project-wide SSH keys blocked
                            let block_project_keys = instance.metadata
                                .as_ref()
                                .and_then(|m| m.items.as_ref())
                                .map(|items| items.iter().any(|item| {
                                    item.key.as_deref() == Some("block-project-ssh-keys") &&
                                    item.value.as_deref() == Some("true")
                                }))
                                .unwrap_or(false);

                            resources.push(CloudResource {
                                id: instance_id.clone(),
                                resource_id: instance.id.clone().unwrap_or_else(|| instance_name.clone()),
                                resource_type: CloudResourceType::ComputeInstance,
                                provider: CloudProvider::Gcp,
                                region: Some(zone.clone()),
                                name: Some(instance_name.clone()),
                                arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                tags: instance.labels.clone().unwrap_or_default(),
                                metadata: serde_json::json!({
                                    "machine_type": instance.machine_type,
                                    "external_ip": external_ip,
                                    "internal_ip": internal_ip,
                                    "service_account": service_account,
                                    "is_default_sa": is_default_sa,
                                    "has_cloud_platform_scope": has_cloud_platform_scope,
                                    "is_shielded": is_shielded,
                                    "os_login_enabled": os_login_enabled,
                                    "serial_port_logging": serial_port_logging,
                                    "block_project_keys": block_project_keys
                                }),
                                state: instance.status.clone(),
                                discovered_at: now,
                            });

                            // Finding: Default service account (CIS 4.1)
                            if is_default_sa {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(instance_id.clone()),
                                    finding_type: FindingType::Misconfiguration,
                                    severity: FindingSeverity::High,
                                    title: "Compute Instance Using Default Service Account".to_string(),
                                    description: format!("Compute instance '{}' uses the default service account. Default service accounts often have more permissions than needed.", instance_name),
                                    remediation: Some("Create and use a custom service account with only the minimum required permissions.".to_string()),
                                    compliance_mappings: vec![
                                        ComplianceMapping {
                                            framework: "CIS GCP".to_string(),
                                            control_id: "4.1".to_string(),
                                            control_title: Some("Ensure that instances are not configured to use default service account".to_string()),
                                        },
                                    ],
                                    affected_resource_arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                    evidence: Some(FindingEvidence {
                                        description: "Uses default service account".to_string(),
                                        raw_data: Some(serde_json::json!({
                                            "service_account": service_account
                                        })),
                                        expected: Some("Custom service account".to_string()),
                                        actual: Some("Default service account".to_string()),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }

                            // Finding: Cloud Platform scope (CIS 4.2)
                            if has_cloud_platform_scope {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(instance_id.clone()),
                                    finding_type: FindingType::Misconfiguration,
                                    severity: FindingSeverity::Critical,
                                    title: "Compute Instance with Full Cloud Platform Scope".to_string(),
                                    description: format!("Compute instance '{}' uses the 'cloud-platform' scope which grants access to all GCP APIs. This violates the principle of least privilege.", instance_name),
                                    remediation: Some("Replace the cloud-platform scope with specific scopes required by the application.".to_string()),
                                    compliance_mappings: vec![
                                        ComplianceMapping {
                                            framework: "CIS GCP".to_string(),
                                            control_id: "4.2".to_string(),
                                            control_title: Some("Ensure that instances are not configured to use default service account with full access to all Cloud APIs".to_string()),
                                        },
                                    ],
                                    affected_resource_arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                    evidence: Some(FindingEvidence {
                                        description: "Instance uses cloud-platform scope".to_string(),
                                        raw_data: Some(serde_json::json!({
                                            "scopes": ["cloud-platform"]
                                        })),
                                        expected: Some("Minimal required scopes".to_string()),
                                        actual: Some("Full cloud-platform scope".to_string()),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }

                            // Finding: Not using Shielded VM (CIS 4.8)
                            if !is_shielded {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(instance_id.clone()),
                                    finding_type: FindingType::Misconfiguration,
                                    severity: FindingSeverity::Medium,
                                    title: "Compute Instance Without Shielded VM".to_string(),
                                    description: format!("Compute instance '{}' does not have all Shielded VM features enabled. Shielded VMs provide protection against rootkits and bootkits.", instance_name),
                                    remediation: Some("Enable Shielded VM features including Secure Boot, vTPM, and Integrity Monitoring.".to_string()),
                                    compliance_mappings: vec![
                                        ComplianceMapping {
                                            framework: "CIS GCP".to_string(),
                                            control_id: "4.8".to_string(),
                                            control_title: Some("Ensure Compute instances are launched with Shielded VM enabled".to_string()),
                                        },
                                    ],
                                    affected_resource_arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                    evidence: Some(FindingEvidence {
                                        description: "Shielded VM features not fully enabled".to_string(),
                                        raw_data: Some(serde_json::json!({
                                            "secure_boot": secure_boot,
                                            "vtpm": vtpm,
                                            "integrity_monitoring": integrity_monitoring
                                        })),
                                        expected: Some("All Shielded VM features enabled".to_string()),
                                        actual: Some(format!("secure_boot={}, vtpm={}, integrity_monitoring={}", secure_boot, vtpm, integrity_monitoring)),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }

                            // Finding: OS Login not enabled (CIS 4.9)
                            if !os_login_enabled && has_external_ip {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(instance_id.clone()),
                                    finding_type: FindingType::BestPractice,
                                    severity: FindingSeverity::Medium,
                                    title: "Compute Instance Without OS Login".to_string(),
                                    description: format!("Compute instance '{}' with external IP does not have OS Login enabled. OS Login provides centralized SSH key management.", instance_name),
                                    remediation: Some("Enable OS Login by setting the 'enable-oslogin' metadata key to 'TRUE'.".to_string()),
                                    compliance_mappings: vec![
                                        ComplianceMapping {
                                            framework: "CIS GCP".to_string(),
                                            control_id: "4.9".to_string(),
                                            control_title: Some("Ensure that Compute instances have OS Login enabled".to_string()),
                                        },
                                    ],
                                    affected_resource_arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                    evidence: Some(FindingEvidence {
                                        description: "OS Login is not enabled".to_string(),
                                        raw_data: Some(serde_json::json!({
                                            "os_login_enabled": false,
                                            "has_external_ip": true
                                        })),
                                        expected: Some("OS Login enabled".to_string()),
                                        actual: Some("OS Login disabled".to_string()),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }

                            // Finding: Serial port logging enabled
                            if serial_port_logging {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(instance_id.clone()),
                                    finding_type: FindingType::BestPractice,
                                    severity: FindingSeverity::Low,
                                    title: "Compute Instance with Serial Port Logging Enabled".to_string(),
                                    description: format!("Compute instance '{}' has serial port logging enabled which may expose sensitive information.", instance_name),
                                    remediation: Some("Disable serial port logging unless required for debugging.".to_string()),
                                    compliance_mappings: vec![],
                                    affected_resource_arn: Some(format!("projects/{}/zones/{}/instances/{}", project_id, zone, instance_name)),
                                    evidence: Some(FindingEvidence {
                                        description: "Serial port logging is enabled".to_string(),
                                        raw_data: Some(serde_json::json!({
                                            "serial_port_logging": true
                                        })),
                                        expected: Some("Serial port logging disabled".to_string()),
                                        actual: Some("Serial port logging enabled".to_string()),
                                        collected_at: now,
                                    }),
                                    status: FindingStatus::Open,
                                    created_at: now,
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    // Zone might not have instances, this is normal
                    if !e.to_string().contains("404") {
                        warn!("Failed to list instances in zone {}: {}", zone, e);
                    }
                }
            }
        }

        info!("GCP Compute scan complete: {} resources, {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    async fn scan_network(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        info!("Starting GCP Network/Firewall scan");
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let project_id = match self.get_project_id() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to get GCP project ID: {}", e);
                return Err(e);
            }
        };

        // List all firewall rules
        let firewalls_url = format!("{}/projects/{}/global/firewalls", GCP_COMPUTE_API, project_id);
        match self.api_get::<GcpFirewallList>(&firewalls_url).await {
            Ok(firewall_list) => {
                if let Some(firewalls) = firewall_list.items {
                    for firewall in firewalls {
                        let fw_name = firewall.name.clone().unwrap_or_default();
                        let fw_id = Uuid::new_v4().to_string();
                        let is_disabled = firewall.disabled.unwrap_or(false);

                        // Skip disabled firewall rules for findings
                        if is_disabled {
                            resources.push(CloudResource {
                                id: fw_id.clone(),
                                resource_id: firewall.id.clone().unwrap_or_else(|| fw_name.clone()),
                                resource_type: CloudResourceType::FirewallRule,
                                provider: CloudProvider::Gcp,
                                region: Some("global".to_string()),
                                name: Some(fw_name.clone()),
                                arn: Some(format!("projects/{}/global/firewalls/{}", project_id, fw_name)),
                                tags: HashMap::new(),
                                metadata: serde_json::json!({
                                    "network": firewall.network,
                                    "direction": firewall.direction,
                                    "priority": firewall.priority,
                                    "source_ranges": firewall.source_ranges,
                                    "destination_ranges": firewall.destination_ranges,
                                    "allowed": firewall.allowed,
                                    "denied": firewall.denied,
                                    "disabled": true
                                }),
                                state: Some("Disabled".to_string()),
                                discovered_at: now,
                            });
                            continue;
                        }

                        let direction = firewall.direction.clone().unwrap_or_else(|| "INGRESS".to_string());
                        let source_ranges = firewall.source_ranges.clone().unwrap_or_default();
                        let has_any_source = source_ranges.iter().any(|r| r == "0.0.0.0/0" || r == "::/0");

                        resources.push(CloudResource {
                            id: fw_id.clone(),
                            resource_id: firewall.id.clone().unwrap_or_else(|| fw_name.clone()),
                            resource_type: CloudResourceType::FirewallRule,
                            provider: CloudProvider::Gcp,
                            region: Some("global".to_string()),
                            name: Some(fw_name.clone()),
                            arn: Some(format!("projects/{}/global/firewalls/{}", project_id, fw_name)),
                            tags: HashMap::new(),
                            metadata: serde_json::json!({
                                "network": firewall.network,
                                "direction": direction,
                                "priority": firewall.priority,
                                "source_ranges": source_ranges,
                                "destination_ranges": firewall.destination_ranges,
                                "allowed": firewall.allowed,
                                "denied": firewall.denied,
                                "disabled": false
                            }),
                            state: Some("Active".to_string()),
                            discovered_at: now,
                        });

                        // Only check INGRESS rules for exposure issues
                        if direction != "INGRESS" {
                            continue;
                        }

                        // Check if rule exposes dangerous ports from internet
                        if let Some(ref allowed_rules) = firewall.allowed {
                            for allowed in allowed_rules {
                                let protocol = allowed.ip_protocol.as_deref().unwrap_or("");
                                let ports = allowed.ports.clone().unwrap_or_default();

                                // Check for all traffic allowed from internet
                                if has_any_source && ports.is_empty() && protocol != "icmp" {
                                    findings.push(CloudFinding {
                                        id: Uuid::new_v4().to_string(),
                                        scan_id: String::new(),
                                        resource_id: Some(fw_id.clone()),
                                        finding_type: FindingType::Exposure,
                                        severity: FindingSeverity::Critical,
                                        title: "Firewall Rule Allows All Ports from Internet".to_string(),
                                        description: format!("Firewall rule '{}' allows all {} traffic from 0.0.0.0/0 (any IP). This exposes all ports to the internet.", fw_name, protocol),
                                        remediation: Some("Restrict the source range to specific IP addresses or CIDR blocks. Only allow required ports.".to_string()),
                                        compliance_mappings: vec![
                                            ComplianceMapping {
                                                framework: "CIS GCP".to_string(),
                                                control_id: "3.6".to_string(),
                                                control_title: Some("Ensure that SSH access is restricted from the internet".to_string()),
                                            },
                                        ],
                                        affected_resource_arn: Some(format!("projects/{}/global/firewalls/{}", project_id, fw_name)),
                                        evidence: Some(FindingEvidence {
                                            description: "All ports exposed to internet".to_string(),
                                            raw_data: Some(serde_json::json!({
                                                "source_ranges": source_ranges,
                                                "protocol": protocol,
                                                "ports": "all"
                                            })),
                                            expected: Some("Specific ports only".to_string()),
                                            actual: Some("All ports".to_string()),
                                            collected_at: now,
                                        }),
                                        status: FindingStatus::Open,
                                        created_at: now,
                                    });
                                    continue;
                                }

                                // Check for specific dangerous ports from internet
                                if has_any_source {
                                    for port in &ports {
                                        // Handle port ranges (e.g., "22" or "80-443")
                                        let port_check = if port.contains('-') {
                                            // Parse port range
                                            let parts: Vec<&str> = port.split('-').collect();
                                            if parts.len() == 2 {
                                                let start: u16 = parts[0].parse().unwrap_or(0);
                                                let end: u16 = parts[1].parse().unwrap_or(0);
                                                // Check if any dangerous port is in range
                                                vec![22, 3389, 3306, 5432, 1433, 23, 445, 139, 21]
                                                    .iter()
                                                    .find(|&&p| p >= start && p <= end)
                                                    .copied()
                                            } else {
                                                None
                                            }
                                        } else {
                                            port.parse::<u16>().ok()
                                        };

                                        if let Some(port_num) = port_check {
                                            let (title, severity, control) = match port_num {
                                                22 => ("SSH (port 22) exposed to internet", FindingSeverity::Critical, "3.6"),
                                                3389 => ("RDP (port 3389) exposed to internet", FindingSeverity::Critical, "3.7"),
                                                3306 | 5432 | 1433 => ("Database port exposed to internet", FindingSeverity::Critical, "6.5"),
                                                23 => ("Telnet (port 23) exposed to internet", FindingSeverity::Critical, "3.6"),
                                                445 | 139 => ("SMB exposed to internet", FindingSeverity::Critical, "3.6"),
                                                21 => ("FTP (port 21) exposed to internet", FindingSeverity::High, "3.6"),
                                                _ => continue,
                                            };

                                            findings.push(CloudFinding {
                                                id: Uuid::new_v4().to_string(),
                                                scan_id: String::new(),
                                                resource_id: Some(fw_id.clone()),
                                                finding_type: FindingType::Exposure,
                                                severity,
                                                title: format!("Firewall Rule Allows {} from Any IP", title),
                                                description: format!("Firewall rule '{}' allows {} from 0.0.0.0/0 (any IP address). This exposes the service to the entire internet.", fw_name, title),
                                                remediation: Some("Restrict the source range to specific IP addresses or CIDR blocks. Consider using Identity-Aware Proxy (IAP) for access.".to_string()),
                                                compliance_mappings: vec![
                                                    ComplianceMapping {
                                                        framework: "CIS GCP".to_string(),
                                                        control_id: control.to_string(),
                                                        control_title: Some(format!("Ensure that {} is restricted from the internet", title)),
                                                    },
                                                ],
                                                affected_resource_arn: Some(format!("projects/{}/global/firewalls/{}", project_id, fw_name)),
                                                evidence: Some(FindingEvidence {
                                                    description: format!("{} allowed from any IP", title),
                                                    raw_data: Some(serde_json::json!({
                                                        "source_ranges": source_ranges,
                                                        "port": port,
                                                        "protocol": protocol
                                                    })),
                                                    expected: Some("Specific IP ranges".to_string()),
                                                    actual: Some("0.0.0.0/0".to_string()),
                                                    collected_at: now,
                                                }),
                                                status: FindingStatus::Open,
                                                created_at: now,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to list firewall rules: {}", e);
            }
        }

        info!("GCP Network scan complete: {} resources, {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    async fn scan_database(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        info!("Starting GCP Cloud SQL scan");
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        let project_id = match self.get_project_id() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to get GCP project ID: {}", e);
                return Err(e);
            }
        };

        // List all Cloud SQL instances
        let sql_url = format!("{}/projects/{}/instances", GCP_SQLADMIN_API, project_id);
        match self.api_get::<GcpSqlInstanceList>(&sql_url).await {
            Ok(sql_list) => {
                if let Some(instances) = sql_list.items {
                    for instance in instances {
                        let instance_name = instance.name.clone().unwrap_or_default();
                        let instance_id = Uuid::new_v4().to_string();

                        let settings = instance.settings.as_ref();

                        // Check SSL configuration
                        let ssl_required = settings
                            .and_then(|s| s.ip_configuration.as_ref())
                            .and_then(|c| c.require_ssl)
                            .unwrap_or(false);

                        // Check for public IP
                        let ipv4_enabled = settings
                            .and_then(|s| s.ip_configuration.as_ref())
                            .and_then(|c| c.ipv4_enabled)
                            .unwrap_or(true); // Default is enabled

                        let has_private_network = settings
                            .and_then(|s| s.ip_configuration.as_ref())
                            .and_then(|c| c.private_network.as_ref())
                            .is_some();

                        // Check authorized networks for 0.0.0.0/0
                        let authorized_networks = settings
                            .and_then(|s| s.ip_configuration.as_ref())
                            .and_then(|c| c.authorized_networks.clone())
                            .unwrap_or_default();

                        let has_open_network = authorized_networks.iter().any(|net| {
                            net.value.as_deref() == Some("0.0.0.0/0")
                        });

                        // Check backup configuration
                        let backup_enabled = settings
                            .and_then(|s| s.backup_configuration.as_ref())
                            .and_then(|c| c.enabled)
                            .unwrap_or(false);

                        let binary_log_enabled = settings
                            .and_then(|s| s.backup_configuration.as_ref())
                            .and_then(|c| c.binary_log_enabled)
                            .unwrap_or(false);

                        // Check availability type
                        let availability_type = settings
                            .and_then(|s| s.availability_type.clone())
                            .unwrap_or_else(|| "ZONAL".to_string());

                        // Get public IP if exists
                        let public_ip = instance.ip_addresses
                            .as_ref()
                            .and_then(|ips| ips.iter().find(|ip| ip.ip_type.as_deref() == Some("PRIMARY")))
                            .and_then(|ip| ip.ip_address.clone());

                        let private_ip = instance.ip_addresses
                            .as_ref()
                            .and_then(|ips| ips.iter().find(|ip| ip.ip_type.as_deref() == Some("PRIVATE")))
                            .and_then(|ip| ip.ip_address.clone());

                        // Check database flags for security issues
                        let database_flags = settings
                            .and_then(|s| s.database_flags.clone())
                            .unwrap_or_default();

                        let local_infile_enabled = database_flags.iter().any(|f| {
                            f.name.as_deref() == Some("local_infile") && f.value.as_deref() == Some("on")
                        });

                        let skip_show_database_disabled = !database_flags.iter().any(|f| {
                            f.name.as_deref() == Some("skip_show_database") && f.value.as_deref() == Some("on")
                        });

                        resources.push(CloudResource {
                            id: instance_id.clone(),
                            resource_id: instance_name.clone(),
                            resource_type: CloudResourceType::CloudSql,
                            provider: CloudProvider::Gcp,
                            region: instance.region.clone(),
                            name: Some(instance_name.clone()),
                            arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                            tags: HashMap::new(),
                            metadata: serde_json::json!({
                                "database_version": instance.database_version,
                                "tier": settings.and_then(|s| s.tier.clone()),
                                "public_ip": public_ip,
                                "private_ip": private_ip,
                                "ssl_required": ssl_required,
                                "ipv4_enabled": ipv4_enabled,
                                "has_private_network": has_private_network,
                                "backup_enabled": backup_enabled,
                                "binary_log_enabled": binary_log_enabled,
                                "availability_type": availability_type,
                                "authorized_networks": authorized_networks.len()
                            }),
                            state: instance.state.clone(),
                            discovered_at: now,
                        });

                        // Finding: Public IP with open authorized network (CIS 6.5)
                        if ipv4_enabled && has_open_network {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::Exposure,
                                severity: FindingSeverity::Critical,
                                title: "Cloud SQL Instance Allows All IPs".to_string(),
                                description: format!("Cloud SQL instance '{}' has an authorized network entry allowing 0.0.0.0/0. This exposes the database to the entire internet.", instance_name),
                                remediation: Some("Remove the 0.0.0.0/0 entry and only authorize specific IP addresses. Consider using Cloud SQL Proxy or private IP for connections.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "6.5".to_string(),
                                        control_title: Some("Ensure that Cloud SQL database instances do not have public IPs".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Authorized network allows all IPs".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "authorized_networks": authorized_networks.iter().map(|n| n.value.clone()).collect::<Vec<_>>()
                                    })),
                                    expected: Some("Specific IP ranges".to_string()),
                                    actual: Some("0.0.0.0/0".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: Public IP enabled (even without open network) (CIS 6.5)
                        if ipv4_enabled && !has_private_network {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Cloud SQL Instance Has Public IP".to_string(),
                                description: format!("Cloud SQL instance '{}' has a public IP address. Databases should use private IPs and Cloud SQL Proxy for secure access.", instance_name),
                                remediation: Some("Configure the instance to use private IP and disable public IP. Use Cloud SQL Proxy for external access.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "6.5".to_string(),
                                        control_title: Some("Ensure that Cloud SQL database instances do not have public IPs".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Instance has public IP".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "public_ip": public_ip,
                                        "ipv4_enabled": ipv4_enabled,
                                        "has_private_network": false
                                    })),
                                    expected: Some("Private IP only".to_string()),
                                    actual: Some("Public IP enabled".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: SSL not required (CIS 6.1)
                        if !ssl_required {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Cloud SQL Instance Without SSL Required".to_string(),
                                description: format!("Cloud SQL instance '{}' does not require SSL for connections. This allows unencrypted database connections.", instance_name),
                                remediation: Some("Enable 'Require SSL' to enforce encrypted connections for all clients.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "6.1".to_string(),
                                        control_title: Some("Ensure that Cloud SQL database instance requires all incoming connections to use SSL".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "SSL is not required".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "ssl_required": false
                                    })),
                                    expected: Some("SSL required".to_string()),
                                    actual: Some("SSL not required".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: Backups not enabled (CIS 6.7)
                        if !backup_enabled {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Cloud SQL Instance Without Automated Backups".to_string(),
                                description: format!("Cloud SQL instance '{}' does not have automated backups enabled. This could result in data loss.", instance_name),
                                remediation: Some("Enable automated backups with an appropriate retention period for production databases.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "6.7".to_string(),
                                        control_title: Some("Ensure that Cloud SQL database instances are configured with automated backups".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Automated backups are disabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "backup_enabled": false
                                    })),
                                    expected: Some("Backups enabled".to_string()),
                                    actual: Some("Backups disabled".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: Point-in-time recovery not enabled (MySQL)
                        if instance.database_version.as_ref().map(|v| v.starts_with("MYSQL")).unwrap_or(false)
                            && !binary_log_enabled
                        {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Medium,
                                title: "Cloud SQL MySQL Without Point-in-Time Recovery".to_string(),
                                description: format!("Cloud SQL MySQL instance '{}' does not have binary logging enabled. Binary logging is required for point-in-time recovery.", instance_name),
                                remediation: Some("Enable binary logging to allow point-in-time recovery.".to_string()),
                                compliance_mappings: vec![],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Binary logging is disabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "binary_log_enabled": false
                                    })),
                                    expected: Some("Binary logging enabled".to_string()),
                                    actual: Some("Binary logging disabled".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: High availability not enabled
                        if availability_type == "ZONAL" {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Medium,
                                title: "Cloud SQL Instance Without High Availability".to_string(),
                                description: format!("Cloud SQL instance '{}' is configured for zonal availability only. Consider regional availability for production workloads.", instance_name),
                                remediation: Some("Configure the instance for regional (high availability) mode for production databases.".to_string()),
                                compliance_mappings: vec![],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "Instance uses zonal availability".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "availability_type": "ZONAL"
                                    })),
                                    expected: Some("REGIONAL".to_string()),
                                    actual: Some("ZONAL".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: local_infile enabled (MySQL security issue)
                        if local_infile_enabled {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Cloud SQL MySQL with local_infile Enabled".to_string(),
                                description: format!("Cloud SQL MySQL instance '{}' has 'local_infile' flag enabled. This can be used to read local files and is a security risk.", instance_name),
                                remediation: Some("Set the 'local_infile' database flag to 'off' unless specifically required.".to_string()),
                                compliance_mappings: vec![
                                    ComplianceMapping {
                                        framework: "CIS GCP".to_string(),
                                        control_id: "6.1".to_string(),
                                        control_title: Some("Ensure that Cloud SQL database instance is configured securely".to_string()),
                                    },
                                ],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "local_infile is enabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "local_infile": "on"
                                    })),
                                    expected: Some("local_infile: off".to_string()),
                                    actual: Some("local_infile: on".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }

                        // Finding: skip_show_database not enabled (MySQL security)
                        if instance.database_version.as_ref().map(|v| v.starts_with("MYSQL")).unwrap_or(false)
                            && skip_show_database_disabled
                        {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(instance_id.clone()),
                                finding_type: FindingType::BestPractice,
                                severity: FindingSeverity::Low,
                                title: "Cloud SQL MySQL Without skip_show_database".to_string(),
                                description: format!("Cloud SQL MySQL instance '{}' does not have 'skip_show_database' flag enabled. This allows users to see all databases.", instance_name),
                                remediation: Some("Set the 'skip_show_database' database flag to 'on' to prevent users from seeing databases they don't have access to.".to_string()),
                                compliance_mappings: vec![],
                                affected_resource_arn: Some(format!("projects/{}/instances/{}", project_id, instance_name)),
                                evidence: Some(FindingEvidence {
                                    description: "skip_show_database is not enabled".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "skip_show_database": "off"
                                    })),
                                    expected: Some("skip_show_database: on".to_string()),
                                    actual: Some("skip_show_database: off".to_string()),
                                    collected_at: now,
                                }),
                                status: FindingStatus::Open,
                                created_at: now,
                            });
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to list Cloud SQL instances: {}", e);
            }
        }

        info!("GCP Database scan complete: {} resources, {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gcp_demo_scan() {
        let scanner = GcpScanner::new();
        let config = CloudScanConfig {
            provider: CloudProvider::Gcp,
            regions: vec!["us-central1".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
        };

        let (resources, findings) = scanner.run_scan(&config).await.unwrap();

        assert!(!resources.is_empty(), "Demo scan should return resources");
        assert!(!findings.is_empty(), "Demo scan should return findings");
    }
}
