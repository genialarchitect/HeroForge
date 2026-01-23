//! Azure Cloud Infrastructure Scanner
//!
//! This module provides scanning capabilities for Azure cloud resources including:
//! - IAM: Azure AD users, service principals, role assignments
//! - Storage: Storage accounts, blob containers
//! - Compute: Virtual machines, App Services
//! - Network: Network Security Groups, Virtual Networks
//! - Database: Azure SQL, Cosmos DB
//!
//! Real Azure scanning requires the following environment variables:
//! - AZURE_SUBSCRIPTION_ID: The Azure subscription to scan
//! - AZURE_TENANT_ID: Azure AD tenant ID
//! - AZURE_CLIENT_ID: Service principal client ID
//! - AZURE_CLIENT_SECRET: Service principal secret

use super::types::*;
use anyhow::{Context, Result};
use chrono::Utc;
use log::{info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::Mutex;
use uuid::Uuid;

/// Azure Management API base URL
const AZURE_MGMT_API: &str = "https://management.azure.com";
/// Azure Login endpoint for OAuth2
const AZURE_LOGIN_URL: &str = "https://login.microsoftonline.com";

// Azure API response types
#[derive(Debug, Deserialize)]
struct AzureTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct AzureListResponse<T> {
    value: Vec<T>,
    #[serde(rename = "nextLink")]
    #[allow(dead_code)]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureStorageAccount {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<AzureStorageProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureStorageProperties {
    provisioning_state: Option<String>,
    supports_https_traffic_only: Option<bool>,
    minimum_tls_version: Option<String>,
    allow_blob_public_access: Option<bool>,
    network_acls: Option<AzureNetworkAcls>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureNetworkAcls {
    default_action: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureNsg {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<AzureNsgProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureNsgProperties {
    provisioning_state: Option<String>,
    security_rules: Option<Vec<AzureSecurityRule>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSecurityRule {
    name: Option<String>,
    properties: Option<AzureSecurityRuleProperties>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSecurityRuleProperties {
    priority: Option<i32>,
    direction: Option<String>,
    access: Option<String>,
    protocol: Option<String>,
    source_address_prefix: Option<String>,
    source_address_prefixes: Option<Vec<String>>,
    destination_port_range: Option<String>,
    destination_port_ranges: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureVm {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<AzureVmProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureVmProperties {
    provisioning_state: Option<String>,
    hardware_profile: Option<AzureHardwareProfile>,
    storage_profile: Option<AzureStorageProfile>,
    os_profile: Option<AzureOsProfile>,
    network_profile: Option<AzureNetworkProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureHardwareProfile {
    vm_size: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureStorageProfile {
    os_disk: Option<AzureOsDisk>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureOsDisk {
    os_type: Option<String>,
    encryption_settings: Option<AzureEncryptionSettings>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureEncryptionSettings {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureOsProfile {
    computer_name: Option<String>,
    admin_username: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureNetworkProfile {
    network_interfaces: Option<Vec<AzureNetworkInterfaceRef>>,
}

#[derive(Debug, Deserialize)]
struct AzureNetworkInterfaceRef {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureRoleAssignment {
    id: Option<String>,
    name: Option<String>,
    properties: Option<AzureRoleAssignmentProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureRoleAssignmentProperties {
    role_definition_id: Option<String>,
    principal_id: Option<String>,
    principal_type: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSqlServer {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<AzureSqlServerProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureSqlServerProperties {
    state: Option<String>,
    version: Option<String>,
    minimal_tls_version: Option<String>,
    public_network_access: Option<String>,
    administrators: Option<AzureAdministrators>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AzureAdministrators {
    administrator_type: Option<String>,
    azure_ad_only_authentication: Option<bool>,
}

/// Azure Cloud Scanner implementation
pub struct AzureScanner {
    /// Azure subscription ID for scanning
    subscription_id: Option<String>,
    /// Azure tenant ID
    tenant_id: Option<String>,
    /// Azure client ID (service principal)
    client_id: Option<String>,
    /// Azure client secret
    client_secret: Option<String>,
    /// HTTP client for API requests
    client: Client,
    /// Cached access token (protected by mutex for interior mutability)
    access_token: Mutex<Option<String>>,
}

impl AzureScanner {
    /// Create a new Azure scanner
    pub fn new() -> Self {
        let subscription_id = env::var("AZURE_SUBSCRIPTION_ID").ok();
        let tenant_id = env::var("AZURE_TENANT_ID").ok();
        let client_id = env::var("AZURE_CLIENT_ID").ok();
        let client_secret = env::var("AZURE_CLIENT_SECRET").ok();

        let has_creds = subscription_id.is_some()
            && tenant_id.is_some()
            && client_id.is_some()
            && client_secret.is_some();

        if has_creds {
            info!("Azure credentials configured - real scanning available");
        } else {
            warn!("Azure credentials not fully configured - scans will return errors");
        }

        Self {
            subscription_id,
            tenant_id,
            client_id,
            client_secret,
            client: Client::new(),
            access_token: Mutex::new(None),
        }
    }

    /// Check if real API mode is available
    fn api_available(&self) -> bool {
        self.subscription_id.is_some()
            && self.tenant_id.is_some()
            && self.client_id.is_some()
            && self.client_secret.is_some()
    }

    /// Get subscription ID or error
    fn get_subscription_id(&self) -> Result<String> {
        self.subscription_id.clone()
            .ok_or_else(|| anyhow::anyhow!("AZURE_SUBSCRIPTION_ID not set"))
    }

    /// Get OAuth2 access token for Azure Management API
    async fn get_access_token(&self) -> Result<String> {
        // Check cache first
        {
            let cached = self.access_token.lock().unwrap();
            if let Some(ref token) = *cached {
                return Ok(token.clone());
            }
        }

        let tenant_id = self.tenant_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("AZURE_TENANT_ID not set"))?;
        let client_id = self.client_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("AZURE_CLIENT_ID not set"))?;
        let client_secret = self.client_secret.as_ref()
            .ok_or_else(|| anyhow::anyhow!("AZURE_CLIENT_SECRET not set"))?;

        let token_url = format!("{}/{}/oauth2/v2.0/token", AZURE_LOGIN_URL, tenant_id);

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "https://management.azure.com/.default"),
        ];

        let response = self.client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .context("Failed to request Azure access token")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Azure auth failed {}: {}", status, body));
        }

        let token_resp: AzureTokenResponse = response.json().await
            .context("Failed to parse Azure token response")?;

        // Cache the token
        {
            let mut cached = self.access_token.lock().unwrap();
            *cached = Some(token_resp.access_token.clone());
        }
        Ok(token_resp.access_token)
    }

    /// Make an authenticated GET request to Azure Management API
    async fn api_get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let token = self.get_access_token().await?;

        let response = self.client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Failed to make Azure API request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Azure API error {}: {}", status, body));
        }

        response.json::<T>().await.context("Failed to parse Azure API response")
    }

    // =========================================================================
    // Real Azure API Scanning Functions
    // =========================================================================

    /// Scan storage accounts using Azure REST API
    async fn scan_storage_api(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();
        let subscription_id = self.get_subscription_id()?;

        info!("Scanning Azure storage accounts via REST API");

        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
            AZURE_MGMT_API, subscription_id
        );

        let response: AzureListResponse<AzureStorageAccount> = self.api_get(&url).await?;

        for account in response.value {
            let account_name = account.name.clone().unwrap_or_default();
            let account_id = account.id.clone().unwrap_or_default();
            let location = account.location.clone().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            let https_only = account.properties.as_ref()
                .and_then(|p| p.supports_https_traffic_only);
            let min_tls = account.properties.as_ref()
                .and_then(|p| p.minimum_tls_version.clone());
            let blob_public = account.properties.as_ref()
                .and_then(|p| p.allow_blob_public_access);
            let network_default = account.properties.as_ref()
                .and_then(|p| p.network_acls.as_ref())
                .and_then(|n| n.default_action.clone());

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: account_name.clone(),
                resource_type: CloudResourceType::StorageAccount,
                provider: CloudProvider::Azure,
                region: Some(location),
                name: Some(account_name.clone()),
                arn: Some(account_id.clone()),
                tags: account.tags.unwrap_or_default(),
                metadata: serde_json::json!({
                    "https_only": https_only,
                    "minimum_tls_version": min_tls,
                    "allow_blob_public_access": blob_public,
                    "network_default_action": network_default,
                }),
                state: account.properties.as_ref()
                    .and_then(|p| p.provisioning_state.clone()),
                discovered_at: now,
            });

            // Security findings
            if https_only == Some(false) {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: FindingSeverity::High,
                    title: "Storage Account Allows HTTP".to_string(),
                    description: format!("Storage account '{}' allows insecure HTTP traffic.", account_name),
                    remediation: Some("Enable 'Secure transfer required'.".to_string()),
                    compliance_mappings: vec![ComplianceMapping {
                        framework: "CIS Azure".to_string(),
                        control_id: "3.1".to_string(),
                        control_title: Some("Ensure secure transfer required is enabled".to_string()),
                    }],
                    affected_resource_arn: Some(account_id.clone()),
                    evidence: Some(FindingEvidence {
                        description: "HTTPS not enforced".to_string(),
                        raw_data: Some(serde_json::json!({"supportsHttpsTrafficOnly": false})),
                        expected: Some("true".to_string()),
                        actual: Some("false".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            if blob_public == Some(true) {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Exposure,
                    severity: FindingSeverity::High,
                    title: "Storage Account Allows Public Blob Access".to_string(),
                    description: format!("Storage account '{}' allows public blob access.", account_name),
                    remediation: Some("Disable public blob access.".to_string()),
                    compliance_mappings: vec![ComplianceMapping {
                        framework: "CIS Azure".to_string(),
                        control_id: "3.7".to_string(),
                        control_title: Some("Ensure public access is disabled".to_string()),
                    }],
                    affected_resource_arn: Some(account_id.clone()),
                    evidence: Some(FindingEvidence {
                        description: "Public blob access enabled".to_string(),
                        raw_data: Some(serde_json::json!({"allowBlobPublicAccess": true})),
                        expected: Some("false".to_string()),
                        actual: Some("true".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            if let Some(ref tls) = min_tls {
                if tls != "TLS1_2" {
                    findings.push(CloudFinding {
                        id: Uuid::new_v4().to_string(),
                        scan_id: String::new(),
                        resource_id: Some(resource_id.clone()),
                        finding_type: FindingType::Misconfiguration,
                        severity: FindingSeverity::Medium,
                        title: "Storage Account Uses Weak TLS".to_string(),
                        description: format!("Storage account '{}' uses TLS version below 1.2.", account_name),
                        remediation: Some("Set minimum TLS version to 1.2.".to_string()),
                        compliance_mappings: vec![],
                        affected_resource_arn: Some(account_id.clone()),
                        evidence: Some(FindingEvidence {
                            description: "Weak TLS version".to_string(),
                            raw_data: Some(serde_json::json!({"minimumTlsVersion": tls})),
                            expected: Some("TLS1_2".to_string()),
                            actual: Some(tls.clone()),
                            collected_at: now,
                        }),
                        status: FindingStatus::Open,
                        created_at: now,
                    });
                }
            }
        }

        info!("Found {} storage accounts with {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    /// Scan network security groups using Azure REST API
    async fn scan_network_api(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();
        let subscription_id = self.get_subscription_id()?;

        info!("Scanning Azure NSGs via REST API");

        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01",
            AZURE_MGMT_API, subscription_id
        );

        let response: AzureListResponse<AzureNsg> = self.api_get(&url).await?;

        for nsg in response.value {
            let nsg_name = nsg.name.clone().unwrap_or_default();
            let nsg_id = nsg.id.clone().unwrap_or_default();
            let location = nsg.location.clone().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            let rules = nsg.properties.as_ref()
                .and_then(|p| p.security_rules.as_ref())
                .cloned()
                .unwrap_or_default();

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: nsg_name.clone(),
                resource_type: CloudResourceType::SecurityGroup,
                provider: CloudProvider::Azure,
                region: Some(location),
                name: Some(nsg_name.clone()),
                arn: Some(nsg_id.clone()),
                tags: nsg.tags.unwrap_or_default(),
                metadata: serde_json::json!({
                    "rules_count": rules.len(),
                }),
                state: nsg.properties.as_ref()
                    .and_then(|p| p.provisioning_state.clone()),
                discovered_at: now,
            });

            // Check for dangerous inbound rules
            for rule in &rules {
                if let Some(props) = &rule.properties {
                    let is_allow = props.access.as_deref() == Some("Allow");
                    let is_inbound = props.direction.as_deref() == Some("Inbound");

                    let source_any = props.source_address_prefix.as_deref() == Some("*")
                        || props.source_address_prefix.as_deref() == Some("0.0.0.0/0")
                        || props.source_address_prefix.as_deref() == Some("Internet")
                        || props.source_address_prefixes.as_ref().map(|v| v.contains(&"*".to_string())).unwrap_or(false);

                    if is_allow && is_inbound && source_any {
                        let port = props.destination_port_range.as_deref().unwrap_or("");
                        let ports = props.destination_port_ranges.as_ref();

                        let dangerous = [("22", "SSH"), ("3389", "RDP"), ("3306", "MySQL"), ("1433", "MSSQL"), ("5432", "PostgreSQL")];

                        for (dp, svc) in &dangerous {
                            let matches = port == *dp || port == "*"
                                || ports.map(|v| v.iter().any(|p| p == *dp || p == "*")).unwrap_or(false);

                            if matches {
                                findings.push(CloudFinding {
                                    id: Uuid::new_v4().to_string(),
                                    scan_id: String::new(),
                                    resource_id: Some(resource_id.clone()),
                                    finding_type: FindingType::Exposure,
                                    severity: FindingSeverity::Critical,
                                    title: format!("NSG Allows {} from Internet", svc),
                                    description: format!("NSG '{}' rule '{}' allows {} from any source.",
                                        nsg_name, rule.name.as_deref().unwrap_or("unknown"), svc),
                                    remediation: Some(format!("Restrict {} to specific IPs.", svc)),
                                    compliance_mappings: vec![ComplianceMapping {
                                        framework: "CIS Azure".to_string(),
                                        control_id: "6.1".to_string(),
                                        control_title: Some("Restrict access from internet".to_string()),
                                    }],
                                    affected_resource_arn: Some(nsg_id.clone()),
                                    evidence: Some(FindingEvidence {
                                        description: format!("{} open to internet", svc),
                                        raw_data: Some(serde_json::json!({
                                            "rule": rule.name,
                                            "port": dp,
                                            "source": "*"
                                        })),
                                        expected: Some("Specific IPs".to_string()),
                                        actual: Some("Any (*)".to_string()),
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

        info!("Found {} NSGs with {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    /// Scan virtual machines using Azure REST API
    async fn scan_compute_api(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();
        let subscription_id = self.get_subscription_id()?;

        info!("Scanning Azure VMs via REST API");

        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01",
            AZURE_MGMT_API, subscription_id
        );

        let response: AzureListResponse<AzureVm> = self.api_get(&url).await?;

        for vm in response.value {
            let vm_name = vm.name.clone().unwrap_or_default();
            let vm_id = vm.id.clone().unwrap_or_default();
            let location = vm.location.clone().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            let vm_size = vm.properties.as_ref()
                .and_then(|p| p.hardware_profile.as_ref())
                .and_then(|h| h.vm_size.clone());
            let os_type = vm.properties.as_ref()
                .and_then(|p| p.storage_profile.as_ref())
                .and_then(|s| s.os_disk.as_ref())
                .and_then(|o| o.os_type.clone());
            let disk_encrypted = vm.properties.as_ref()
                .and_then(|p| p.storage_profile.as_ref())
                .and_then(|s| s.os_disk.as_ref())
                .and_then(|o| o.encryption_settings.as_ref())
                .and_then(|e| e.enabled);

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: vm_name.clone(),
                resource_type: CloudResourceType::VirtualMachine,
                provider: CloudProvider::Azure,
                region: Some(location),
                name: Some(vm_name.clone()),
                arn: Some(vm_id.clone()),
                tags: vm.tags.unwrap_or_default(),
                metadata: serde_json::json!({
                    "vm_size": vm_size,
                    "os_type": os_type,
                    "disk_encrypted": disk_encrypted,
                }),
                state: vm.properties.as_ref()
                    .and_then(|p| p.provisioning_state.clone()),
                discovered_at: now,
            });

            if disk_encrypted != Some(true) {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: FindingSeverity::Medium,
                    title: "VM Disk Not Encrypted".to_string(),
                    description: format!("VM '{}' OS disk is not encrypted.", vm_name),
                    remediation: Some("Enable Azure Disk Encryption.".to_string()),
                    compliance_mappings: vec![ComplianceMapping {
                        framework: "CIS Azure".to_string(),
                        control_id: "7.1".to_string(),
                        control_title: Some("Ensure VM disks are encrypted".to_string()),
                    }],
                    affected_resource_arn: Some(vm_id.clone()),
                    evidence: Some(FindingEvidence {
                        description: "Disk encryption not enabled".to_string(),
                        raw_data: Some(serde_json::json!({"encryptionEnabled": disk_encrypted})),
                        expected: Some("true".to_string()),
                        actual: Some(format!("{:?}", disk_encrypted)),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }
        }

        info!("Found {} VMs with {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    /// Scan IAM role assignments using Azure REST API
    async fn scan_iam_api(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();
        let subscription_id = self.get_subscription_id()?;

        info!("Scanning Azure role assignments via REST API");

        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
            AZURE_MGMT_API, subscription_id
        );

        let response: AzureListResponse<AzureRoleAssignment> = self.api_get(&url).await?;

        for assignment in response.value {
            let assignment_id = assignment.id.clone().unwrap_or_default();
            let assignment_name = assignment.name.clone().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            let role_def_id = assignment.properties.as_ref()
                .and_then(|p| p.role_definition_id.clone());
            let principal_id = assignment.properties.as_ref()
                .and_then(|p| p.principal_id.clone());
            let principal_type = assignment.properties.as_ref()
                .and_then(|p| p.principal_type.clone());
            let scope = assignment.properties.as_ref()
                .and_then(|p| p.scope.clone());

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: assignment_name.clone(),
                resource_type: CloudResourceType::ServiceAccount,
                provider: CloudProvider::Azure,
                region: Some("global".to_string()),
                name: Some(format!("Role Assignment: {}", assignment_name)),
                arn: Some(assignment_id.clone()),
                tags: HashMap::new(),
                metadata: serde_json::json!({
                    "role_definition_id": role_def_id,
                    "principal_id": principal_id,
                    "principal_type": principal_type,
                    "scope": scope,
                }),
                state: Some("Active".to_string()),
                discovered_at: now,
            });

            // Check for Owner role at subscription scope
            if let Some(ref role_def) = role_def_id {
                // Owner role GUID: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635
                if role_def.contains("8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
                    if let Some(ref s) = scope {
                        if s.starts_with("/subscriptions/") && !s.contains("/resourceGroups/") {
                            findings.push(CloudFinding {
                                id: Uuid::new_v4().to_string(),
                                scan_id: String::new(),
                                resource_id: Some(resource_id.clone()),
                                finding_type: FindingType::Misconfiguration,
                                severity: FindingSeverity::High,
                                title: "Owner Role at Subscription Scope".to_string(),
                                description: format!("Principal {:?} has Owner role at subscription level.", principal_type),
                                remediation: Some("Use least privilege - assign specific roles.".to_string()),
                                compliance_mappings: vec![ComplianceMapping {
                                    framework: "CIS Azure".to_string(),
                                    control_id: "1.23".to_string(),
                                    control_title: Some("Use least privilege".to_string()),
                                }],
                                affected_resource_arn: Some(assignment_id.clone()),
                                evidence: Some(FindingEvidence {
                                    description: "Owner role at subscription".to_string(),
                                    raw_data: Some(serde_json::json!({
                                        "role": "Owner",
                                        "scope": s
                                    })),
                                    expected: Some("Resource-scoped roles".to_string()),
                                    actual: Some("Subscription-scoped Owner".to_string()),
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

        info!("Found {} role assignments with {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

    /// Scan SQL servers using Azure REST API
    async fn scan_database_api(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();
        let subscription_id = self.get_subscription_id()?;

        info!("Scanning Azure SQL servers via REST API");

        let url = format!(
            "{}/subscriptions/{}/providers/Microsoft.Sql/servers?api-version=2023-02-01-preview",
            AZURE_MGMT_API, subscription_id
        );

        let response: AzureListResponse<AzureSqlServer> = self.api_get(&url).await?;

        for server in response.value {
            let server_name = server.name.clone().unwrap_or_default();
            let server_id = server.id.clone().unwrap_or_default();
            let location = server.location.clone().unwrap_or_default();

            let resource_id = Uuid::new_v4().to_string();

            let min_tls = server.properties.as_ref()
                .and_then(|p| p.minimal_tls_version.clone());
            let public_access = server.properties.as_ref()
                .and_then(|p| p.public_network_access.clone());
            let has_aad_admin = server.properties.as_ref()
                .and_then(|p| p.administrators.as_ref())
                .map(|a| a.administrator_type.is_some())
                .unwrap_or(false);

            resources.push(CloudResource {
                id: resource_id.clone(),
                resource_id: server_name.clone(),
                resource_type: CloudResourceType::SqlServer,
                provider: CloudProvider::Azure,
                region: Some(location),
                name: Some(server_name.clone()),
                arn: Some(server_id.clone()),
                tags: server.tags.unwrap_or_default(),
                metadata: serde_json::json!({
                    "minimal_tls_version": min_tls,
                    "public_network_access": public_access,
                    "has_aad_admin": has_aad_admin,
                }),
                state: server.properties.as_ref()
                    .and_then(|p| p.state.clone()),
                discovered_at: now,
            });

            if !has_aad_admin {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Misconfiguration,
                    severity: FindingSeverity::High,
                    title: "SQL Server Without Azure AD Admin".to_string(),
                    description: format!("SQL Server '{}' has no Azure AD administrator.", server_name),
                    remediation: Some("Configure an Azure AD administrator.".to_string()),
                    compliance_mappings: vec![ComplianceMapping {
                        framework: "CIS Azure".to_string(),
                        control_id: "4.4".to_string(),
                        control_title: Some("Configure Azure AD admin for SQL".to_string()),
                    }],
                    affected_resource_arn: Some(server_id.clone()),
                    evidence: Some(FindingEvidence {
                        description: "No Azure AD admin".to_string(),
                        raw_data: Some(serde_json::json!({"hasAadAdmin": false})),
                        expected: Some("Azure AD admin configured".to_string()),
                        actual: Some("No Azure AD admin".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }

            if public_access.as_deref() == Some("Enabled") {
                findings.push(CloudFinding {
                    id: Uuid::new_v4().to_string(),
                    scan_id: String::new(),
                    resource_id: Some(resource_id.clone()),
                    finding_type: FindingType::Exposure,
                    severity: FindingSeverity::High,
                    title: "SQL Server Public Network Access Enabled".to_string(),
                    description: format!("SQL Server '{}' allows public network access.", server_name),
                    remediation: Some("Disable public network access and use private endpoints.".to_string()),
                    compliance_mappings: vec![],
                    affected_resource_arn: Some(server_id.clone()),
                    evidence: Some(FindingEvidence {
                        description: "Public access enabled".to_string(),
                        raw_data: Some(serde_json::json!({"publicNetworkAccess": "Enabled"})),
                        expected: Some("Disabled".to_string()),
                        actual: Some("Enabled".to_string()),
                        collected_at: now,
                    }),
                    status: FindingStatus::Open,
                    created_at: now,
                });
            }
        }

        info!("Found {} SQL servers with {} findings", resources.len(), findings.len());
        Ok((resources, findings))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_api_available() {
        let scanner = AzureScanner::new();
        // Without environment variables set, api_available should reflect credential state
        let has_creds = std::env::var("AZURE_SUBSCRIPTION_ID").is_ok()
            && std::env::var("AZURE_TENANT_ID").is_ok()
            && std::env::var("AZURE_CLIENT_ID").is_ok()
            && std::env::var("AZURE_CLIENT_SECRET").is_ok();
        assert_eq!(scanner.api_available(), has_creds);
    }
}

#[async_trait::async_trait]
impl CloudScanner for AzureScanner {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    async fn scan_iam(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if !self.api_available() {
            anyhow::bail!("Azure credentials not configured. Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
        }
        info!("Azure IAM scanning using REST API");
        self.scan_iam_api().await
    }

    async fn scan_storage(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if !self.api_available() {
            anyhow::bail!("Azure credentials not configured. Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
        }
        info!("Azure Storage scanning using REST API");
        self.scan_storage_api().await
    }

    async fn scan_compute(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if !self.api_available() {
            anyhow::bail!("Azure credentials not configured. Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
        }
        info!("Azure Compute scanning using REST API");
        self.scan_compute_api().await
    }

    async fn scan_network(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if !self.api_available() {
            anyhow::bail!("Azure credentials not configured. Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
        }
        info!("Azure Network scanning using REST API");
        self.scan_network_api().await
    }

    async fn scan_database(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if !self.api_available() {
            anyhow::bail!("Azure credentials not configured. Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
        }
        info!("Azure Database scanning using REST API");
        self.scan_database_api().await
    }
}
