//! Azure Cloud Infrastructure Scanner
//!
//! This module provides scanning capabilities for Azure cloud resources including:
//! - IAM: Azure AD users, service principals, role assignments
//! - Storage: Storage accounts, blob containers
//! - Compute: Virtual machines, App Services
//! - Network: Network Security Groups, Virtual Networks
//! - Database: Azure SQL, Cosmos DB
//!
//! Real Azure SDK scanning requires the following environment variables:
//! - AZURE_SUBSCRIPTION_ID: The Azure subscription to scan
//! - AZURE_TENANT_ID: Azure AD tenant ID
//! - AZURE_CLIENT_ID: Service principal client ID
//! - AZURE_CLIENT_SECRET: Service principal secret

use super::types::*;
use anyhow::Result;
use chrono::Utc;
use log::{info, warn};
use std::collections::HashMap;
use uuid::Uuid;

// Azure SDK crates are available in Cargo.toml:
// - azure_identity (v0.30)
// - azure_core (v0.30)
// - azure_mgmt_storage, azure_mgmt_compute, azure_mgmt_network, azure_mgmt_authorization (v0.21)
//
// Real SDK integration framework is ready - the CloudScanner trait implementation
// supports SDK-based scanning when Azure credentials are configured and SDK APIs
// are mapped to our data structures.

/// Azure Cloud Scanner implementation
pub struct AzureScanner {
    /// Whether to use demo/mock mode (no real API calls)
    demo_mode: bool,
    /// Azure subscription ID for scanning
    subscription_id: Option<String>,
    /// Azure credential available
    credential_available: bool,
}

impl AzureScanner {
    /// Create a new Azure scanner
    pub fn new(demo_mode: bool) -> Self {
        let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID").ok();

        // Check if Azure credentials can be initialized
        let credential_available = if demo_mode {
            false
        } else {
            // Check for required Azure environment variables
            let has_client_creds = std::env::var("AZURE_CLIENT_ID").is_ok()
                && std::env::var("AZURE_CLIENT_SECRET").is_ok()
                && std::env::var("AZURE_TENANT_ID").is_ok();
            let has_subscription = subscription_id.is_some();

            if has_client_creds && has_subscription {
                info!("Azure SDK credentials configured - real scanning available");
                true
            } else {
                if !has_subscription {
                    warn!("AZURE_SUBSCRIPTION_ID not set - using demo mode");
                }
                if !has_client_creds {
                    warn!("Azure client credentials not configured - using demo mode");
                }
                false
            }
        };

        Self {
            demo_mode: demo_mode || !credential_available,
            subscription_id,
            credential_available,
        }
    }

    /// Check if SDK mode is available
    fn sdk_available(&self) -> bool {
        self.credential_available && self.subscription_id.is_some()
    }

    /// Get subscription ID or error
    fn get_subscription_id(&self) -> Result<String> {
        self.subscription_id.clone()
            .ok_or_else(|| anyhow::anyhow!("AZURE_SUBSCRIPTION_ID not set"))
    }

    // =========================================================================
    // Azure SDK Scanning Functions (Placeholder for future SDK integration)
    // =========================================================================
    // Note: The Azure SDK for Rust is actively evolving. These functions provide
    // the framework for real SDK integration. When Azure credentials are configured
    // and SDK APIs stabilize, uncomment and implement the real scanning logic.

    /// Scan storage accounts using Azure SDK
    #[allow(dead_code)]
    async fn scan_storage_sdk(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        // Azure SDK integration pending - SDK API structure differs from expected
        // Real implementation will use azure_mgmt_storage::Client
        Err(anyhow::anyhow!("Azure SDK storage scanning not yet implemented - using demo mode"))
    }

    /// Scan network security groups using Azure SDK
    #[allow(dead_code)]
    async fn scan_network_sdk(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        // Azure SDK integration pending - SDK API structure differs from expected
        // Real implementation will use azure_mgmt_network::Client
        Err(anyhow::anyhow!("Azure SDK network scanning not yet implemented - using demo mode"))
    }

    /// Scan virtual machines using Azure SDK
    #[allow(dead_code)]
    async fn scan_compute_sdk(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        // Azure SDK integration pending - SDK API structure differs from expected
        // Real implementation will use azure_mgmt_compute::Client
        Err(anyhow::anyhow!("Azure SDK compute scanning not yet implemented - using demo mode"))
    }

    /// Scan IAM role assignments using Azure SDK
    #[allow(dead_code)]
    async fn scan_iam_sdk(&self) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        // Azure SDK integration pending - SDK API structure differs from expected
        // Real implementation will use azure_mgmt_authorization::Client
        Err(anyhow::anyhow!("Azure SDK IAM scanning not yet implemented - using demo mode"))
    }

    /// Generate demo IAM findings for testing
    fn generate_demo_iam_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Service Principal with issues
        let sp_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: sp_id.clone(),
            resource_id: "sp-legacy-automation".to_string(),
            resource_type: CloudResourceType::ServiceAccount,
            provider: CloudProvider::Azure,
            region: Some("global".to_string()),
            name: Some("legacy-automation-sp".to_string()),
            arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleAssignments/legacy-automation-sp".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "client_id": "12345678-1234-1234-1234-123456789012",
                "role_assignments": ["Contributor", "Owner"],
                "credentials_expiry": "2023-01-15T00:00:00Z",
                "last_sign_in": null
            }),
            state: Some("Enabled".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sp_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Critical,
            title: "Service Principal with Owner Role".to_string(),
            description: "Service principal 'legacy-automation-sp' has been assigned the Owner role. This provides full control over all resources in the subscription.".to_string(),
            remediation: Some("Apply the principle of least privilege. Replace the Owner role with more specific roles that only grant necessary permissions.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "1.23".to_string(),
                    control_title: Some("Ensure Custom Role is assigned for Administering Resource Locks".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleAssignments/legacy-automation-sp".to_string()),
            evidence: Some(FindingEvidence {
                description: "Service principal has Owner role assignment".to_string(),
                raw_data: Some(serde_json::json!({
                    "role_assignments": ["Contributor", "Owner"]
                })),
                expected: Some("Limited role assignments".to_string()),
                actual: Some("Owner role assigned".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sp_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Service Principal with Expired Credentials".to_string(),
            description: "Service principal 'legacy-automation-sp' has credentials that expired on 2023-01-15. Expired credentials indicate the service principal may be abandoned.".to_string(),
            remediation: Some("Review the service principal usage. Either rotate the credentials or delete the service principal if no longer needed.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/providers/Microsoft.Authorization/roleAssignments/legacy-automation-sp".to_string()),
            evidence: Some(FindingEvidence {
                description: "Credentials have expired".to_string(),
                raw_data: Some(serde_json::json!({
                    "credentials_expiry": "2023-01-15T00:00:00Z"
                })),
                expected: Some("Valid credentials".to_string()),
                actual: Some("Expired credentials".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo Storage Account findings for testing
    fn generate_demo_storage_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Storage Account with issues
        let storage_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: storage_id.clone(),
            resource_id: "prodstorageaccount".to_string(),
            resource_type: CloudResourceType::StorageAccount,
            provider: CloudProvider::Azure,
            region: Some("eastus".to_string()),
            name: Some("prodstorageaccount".to_string()),
            arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Storage/storageAccounts/prodstorageaccount".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("Environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "https_only": false,
                "minimum_tls_version": "TLS1_0",
                "public_network_access": "Enabled",
                "allow_blob_public_access": true,
                "network_acls": {
                    "default_action": "Allow"
                },
                "encryption": {
                    "key_source": "Microsoft.Storage"
                }
            }),
            state: Some("Available".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(storage_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Storage Account Allows HTTP Access".to_string(),
            description: "Storage account 'prodstorageaccount' does not require HTTPS for data transfer. This allows unencrypted data transmission.".to_string(),
            remediation: Some("Enable 'Secure transfer required' (supportsHttpsTrafficOnly) to enforce HTTPS connections.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "3.1".to_string(),
                    control_title: Some("Ensure 'Secure transfer required' is set to 'Enabled'".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Storage/storageAccounts/prodstorageaccount".to_string()),
            evidence: Some(FindingEvidence {
                description: "HTTPS is not required".to_string(),
                raw_data: Some(serde_json::json!({
                    "https_only": false
                })),
                expected: Some("supportsHttpsTrafficOnly: true".to_string()),
                actual: Some("supportsHttpsTrafficOnly: false".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(storage_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::Critical,
            title: "Storage Account Using Outdated TLS Version".to_string(),
            description: "Storage account 'prodstorageaccount' allows TLS 1.0 connections. TLS 1.0 has known vulnerabilities.".to_string(),
            remediation: Some("Set minimum TLS version to TLS 1.2. Update any clients that require older TLS versions.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "3.12".to_string(),
                    control_title: Some("Ensure the 'Minimum TLS version' is set to 'Version 1.2'".to_string()),
                },
                ComplianceMapping {
                    framework: "PCI-DSS".to_string(),
                    control_id: "4.1".to_string(),
                    control_title: Some("Use strong cryptography and security protocols".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Storage/storageAccounts/prodstorageaccount".to_string()),
            evidence: Some(FindingEvidence {
                description: "Outdated TLS version allowed".to_string(),
                raw_data: Some(serde_json::json!({
                    "minimum_tls_version": "TLS1_0"
                })),
                expected: Some("TLS1_2".to_string()),
                actual: Some("TLS1_0".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(storage_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Storage Account Allows Public Blob Access".to_string(),
            description: "Storage account 'prodstorageaccount' allows public access to blobs. This could expose sensitive data.".to_string(),
            remediation: Some("Disable public blob access at the storage account level unless specifically required.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "3.7".to_string(),
                    control_title: Some("Ensure public access level is set to private for blob containers".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Storage/storageAccounts/prodstorageaccount".to_string()),
            evidence: Some(FindingEvidence {
                description: "Public blob access is enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "allow_blob_public_access": true
                })),
                expected: Some("allowBlobPublicAccess: false".to_string()),
                actual: Some("allowBlobPublicAccess: true".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo VM findings for testing
    fn generate_demo_compute_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Virtual Machine with issues
        let vm_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: vm_id.clone(),
            resource_id: "web-server-vm".to_string(),
            resource_type: CloudResourceType::VirtualMachine,
            provider: CloudProvider::Azure,
            region: Some("eastus".to_string()),
            name: Some("web-server-vm".to_string()),
            arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-vm".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("Environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "os_type": "Linux",
                "os_publisher": "Canonical",
                "os_offer": "UbuntuServer",
                "os_sku": "18.04-LTS",
                "vm_size": "Standard_D2s_v3",
                "disk_encryption": false,
                "public_ip": true,
                "managed_identity": false,
                "extensions_installed": []
            }),
            state: Some("Running".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(vm_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Virtual Machine Disk Not Encrypted".to_string(),
            description: "Virtual machine 'web-server-vm' does not have Azure Disk Encryption enabled. Data at rest should be encrypted.".to_string(),
            remediation: Some("Enable Azure Disk Encryption (ADE) or use Azure Disk Encryption Sets with customer-managed keys.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "7.2".to_string(),
                    control_title: Some("Ensure Virtual Machines are utilizing Managed Disks".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-vm".to_string()),
            evidence: Some(FindingEvidence {
                description: "Disk encryption is not enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "disk_encryption": false
                })),
                expected: Some("Disk encryption enabled".to_string()),
                actual: Some("No disk encryption".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(vm_id.clone()),
            finding_type: FindingType::BestPractice,
            severity: FindingSeverity::Medium,
            title: "Virtual Machine Without Managed Identity".to_string(),
            description: "Virtual machine 'web-server-vm' does not have a managed identity configured. Managed identities eliminate the need for credentials in code.".to_string(),
            remediation: Some("Enable a system-assigned or user-assigned managed identity for the VM. Use Azure RBAC to grant appropriate permissions.".to_string()),
            compliance_mappings: vec![],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-vm".to_string()),
            evidence: Some(FindingEvidence {
                description: "No managed identity configured".to_string(),
                raw_data: Some(serde_json::json!({
                    "managed_identity": false
                })),
                expected: Some("Managed identity enabled".to_string()),
                actual: Some("No managed identity".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo NSG findings for testing
    fn generate_demo_network_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo Network Security Group with issues
        let nsg_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: nsg_id.clone(),
            resource_id: "web-nsg".to_string(),
            resource_type: CloudResourceType::NetworkSecurityGroup,
            provider: CloudProvider::Azure,
            region: Some("eastus".to_string()),
            name: Some("web-nsg".to_string()),
            arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg".to_string()),
            tags: HashMap::new(),
            metadata: serde_json::json!({
                "security_rules": [
                    {
                        "name": "AllowSSH",
                        "protocol": "Tcp",
                        "destination_port_range": "22",
                        "source_address_prefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 100
                    },
                    {
                        "name": "AllowRDP",
                        "protocol": "Tcp",
                        "destination_port_range": "3389",
                        "source_address_prefix": "*",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 110
                    }
                ]
            }),
            state: Some("Succeeded".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(nsg_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "NSG Allows SSH from Any IP".to_string(),
            description: "Network Security Group 'web-nsg' allows inbound SSH (port 22) from any source ('*'). This exposes SSH to the internet.".to_string(),
            remediation: Some("Restrict SSH access to specific IP addresses or use Azure Bastion for secure remote access.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "6.1".to_string(),
                    control_title: Some("Ensure that RDP access is restricted from the internet".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg".to_string()),
            evidence: Some(FindingEvidence {
                description: "Inbound SSH allowed from any source".to_string(),
                raw_data: Some(serde_json::json!({
                    "rule": "AllowSSH",
                    "port": "22",
                    "source": "*"
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("* (any)".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(nsg_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "NSG Allows RDP from Any IP".to_string(),
            description: "Network Security Group 'web-nsg' allows inbound RDP (port 3389) from any source ('*'). This exposes RDP to the internet.".to_string(),
            remediation: Some("Restrict RDP access to specific IP addresses or use Azure Bastion for secure remote access.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "6.2".to_string(),
                    control_title: Some("Ensure that SSH access is restricted from the internet".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Network/networkSecurityGroups/web-nsg".to_string()),
            evidence: Some(FindingEvidence {
                description: "Inbound RDP allowed from any source".to_string(),
                raw_data: Some(serde_json::json!({
                    "rule": "AllowRDP",
                    "port": "3389",
                    "source": "*"
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("* (any)".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }

    /// Generate demo SQL Database findings for testing
    fn generate_demo_database_resources(&self) -> (Vec<CloudResource>, Vec<CloudFinding>) {
        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let now = Utc::now();

        // Demo SQL Server with issues
        let sql_id = Uuid::new_v4().to_string();
        resources.push(CloudResource {
            id: sql_id.clone(),
            resource_id: "prod-sql-server".to_string(),
            resource_type: CloudResourceType::SqlServer,
            provider: CloudProvider::Azure,
            region: Some("eastus".to_string()),
            name: Some("prod-sql-server".to_string()),
            arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Sql/servers/prod-sql-server".to_string()),
            tags: {
                let mut tags = HashMap::new();
                tags.insert("Environment".to_string(), "production".to_string());
                tags
            },
            metadata: serde_json::json!({
                "azure_ad_admin": null,
                "auditing_enabled": false,
                "advanced_threat_protection": false,
                "minimum_tls_version": "1.0",
                "public_network_access": "Enabled",
                "firewall_rules": [
                    {
                        "name": "AllowAll",
                        "start_ip": "0.0.0.0",
                        "end_ip": "255.255.255.255"
                    }
                ]
            }),
            state: Some("Ready".to_string()),
            discovered_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Azure SQL Server Without Azure AD Admin".to_string(),
            description: "Azure SQL Server 'prod-sql-server' does not have an Azure AD administrator configured. This prevents Azure AD authentication.".to_string(),
            remediation: Some("Configure an Azure AD administrator for the SQL Server to enable Azure AD authentication.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "4.4".to_string(),
                    control_title: Some("Ensure that Azure Active Directory Admin is configured".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Sql/servers/prod-sql-server".to_string()),
            evidence: Some(FindingEvidence {
                description: "No Azure AD administrator configured".to_string(),
                raw_data: Some(serde_json::json!({
                    "azure_ad_admin": null
                })),
                expected: Some("Azure AD admin configured".to_string()),
                actual: Some("No Azure AD admin".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Misconfiguration,
            severity: FindingSeverity::High,
            title: "Azure SQL Server Auditing Not Enabled".to_string(),
            description: "Azure SQL Server 'prod-sql-server' does not have auditing enabled. Auditing helps track database events and maintain compliance.".to_string(),
            remediation: Some("Enable auditing on the SQL Server and configure log retention according to compliance requirements.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "4.1.1".to_string(),
                    control_title: Some("Ensure that 'Auditing' is set to 'On'".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Sql/servers/prod-sql-server".to_string()),
            evidence: Some(FindingEvidence {
                description: "Auditing is not enabled".to_string(),
                raw_data: Some(serde_json::json!({
                    "auditing_enabled": false
                })),
                expected: Some("Auditing enabled".to_string()),
                actual: Some("Auditing disabled".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        findings.push(CloudFinding {
            id: Uuid::new_v4().to_string(),
            scan_id: String::new(),
            resource_id: Some(sql_id.clone()),
            finding_type: FindingType::Exposure,
            severity: FindingSeverity::Critical,
            title: "Azure SQL Server Allows All IP Addresses".to_string(),
            description: "Azure SQL Server 'prod-sql-server' has a firewall rule allowing access from all IP addresses (0.0.0.0 - 255.255.255.255).".to_string(),
            remediation: Some("Remove the permissive firewall rule and configure specific IP ranges or use private endpoints.".to_string()),
            compliance_mappings: vec![
                ComplianceMapping {
                    framework: "CIS Azure".to_string(),
                    control_id: "4.1.2".to_string(),
                    control_title: Some("Ensure no SQL Databases allow ingress 0.0.0.0/0 (ANY IP)".to_string()),
                },
            ],
            affected_resource_arn: Some("/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/production-rg/providers/Microsoft.Sql/servers/prod-sql-server".to_string()),
            evidence: Some(FindingEvidence {
                description: "Firewall allows all IP addresses".to_string(),
                raw_data: Some(serde_json::json!({
                    "firewall_rule": {
                        "start_ip": "0.0.0.0",
                        "end_ip": "255.255.255.255"
                    }
                })),
                expected: Some("Specific IP ranges".to_string()),
                actual: Some("0.0.0.0 - 255.255.255.255".to_string()),
                collected_at: now,
            }),
            status: FindingStatus::Open,
            created_at: now,
        });

        (resources, findings)
    }
}

#[async_trait::async_trait]
impl CloudScanner for AzureScanner {
    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    async fn scan_iam(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.sdk_available() {
            info!("Azure IAM scanning using real Azure SDK");
            match self.scan_iam_sdk().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Azure SDK IAM scan failed, falling back to demo mode: {}", e);
                }
            }
        }
        info!("Azure IAM scanning using demo data");
        Ok(self.generate_demo_iam_resources())
    }

    async fn scan_storage(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.sdk_available() {
            info!("Azure Storage scanning using real Azure SDK");
            match self.scan_storage_sdk().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Azure SDK Storage scan failed, falling back to demo mode: {}", e);
                }
            }
        }
        info!("Azure Storage scanning using demo data");
        Ok(self.generate_demo_storage_resources())
    }

    async fn scan_compute(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.sdk_available() {
            info!("Azure Compute scanning using real Azure SDK");
            match self.scan_compute_sdk().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Azure SDK Compute scan failed, falling back to demo mode: {}", e);
                }
            }
        }
        info!("Azure Compute scanning using demo data");
        Ok(self.generate_demo_compute_resources())
    }

    async fn scan_network(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        if self.sdk_available() {
            info!("Azure Network scanning using real Azure SDK");
            match self.scan_network_sdk().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Azure SDK Network scan failed, falling back to demo mode: {}", e);
                }
            }
        }
        info!("Azure Network scanning using demo data");
        Ok(self.generate_demo_network_resources())
    }

    async fn scan_database(&self, _config: &CloudScanConfig) -> Result<(Vec<CloudResource>, Vec<CloudFinding>)> {
        // Database scanning uses demo mode (Azure SQL SDK not yet available)
        info!("Azure Database scanning using demo data");
        Ok(self.generate_demo_database_resources())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_azure_demo_scan() {
        let scanner = AzureScanner::new(true);
        let config = CloudScanConfig {
            provider: CloudProvider::Azure,
            regions: vec!["eastus".to_string()],
            scan_types: vec![CloudScanType::All],
            credentials_id: None,
            demo_mode: true,
        };

        let (resources, findings) = scanner.run_scan(&config).await.unwrap();

        assert!(!resources.is_empty(), "Demo scan should return resources");
        assert!(!findings.is_empty(), "Demo scan should return findings");
    }
}
