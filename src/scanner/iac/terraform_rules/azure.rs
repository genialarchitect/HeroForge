//! Azure Terraform Security Rules
//!
//! Comprehensive security rules for Azure resources based on:
//! - CIS Azure Foundations Benchmark
//! - Azure Security Best Practices
//! - Microsoft Security Recommendations

use crate::scanner::iac::rules::{RuleMatcher, RuleMatch};
use crate::scanner::iac::types::*;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Storage Account patterns (line-by-line matching for explicit misconfigurations)
    static ref AZURE_STORAGE_HTTP_ENABLED: Regex = Regex::new(r#"(?i)enable_https_traffic_only\s*=\s*false"#).unwrap();
    static ref AZURE_STORAGE_NO_MIN_TLS: Regex = Regex::new(r#"(?i)min_tls_version\s*=\s*["']TLS1_0["']"#).unwrap();
    static ref AZURE_STORAGE_TLS11: Regex = Regex::new(r#"(?i)min_tls_version\s*=\s*["']TLS1_1["']"#).unwrap();
    static ref AZURE_STORAGE_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref AZURE_STORAGE_BLOB_PUBLIC: Regex = Regex::new(r#"(?i)allow_nested_items_to_be_public\s*=\s*true"#).unwrap();
    static ref AZURE_STORAGE_NO_SOFT_DELETE: Regex = Regex::new(r#"(?i)azurerm_storage_account"#).unwrap();
    static ref AZURE_STORAGE_NO_NETWORK_RULES: Regex = Regex::new(r#"(?i)azurerm_storage_account"#).unwrap();
    static ref AZURE_STORAGE_SHARED_KEY_ENABLED: Regex = Regex::new(r#"(?i)shared_access_key_enabled\s*=\s*true"#).unwrap();
    static ref AZURE_STORAGE_INFRASTRUCTURE_ENCRYPTION_DISABLED: Regex = Regex::new(r#"(?i)infrastructure_encryption_enabled\s*=\s*false"#).unwrap();
    static ref AZURE_STORAGE_QUEUE_LOG_DISABLED: Regex = Regex::new(r#"(?i)delete\s*=\s*false"#).unwrap();

    // SQL/Database patterns
    static ref AZURE_SQL_NO_AUDITING: Regex = Regex::new(r#"(?i)azurerm_mssql_server"#).unwrap();
    static ref AZURE_SQL_NO_TDE: Regex = Regex::new(r#"(?i)transparent_data_encryption_enabled\s*=\s*false"#).unwrap();
    static ref AZURE_SQL_NO_AAD_ADMIN: Regex = Regex::new(r#"(?i)azurerm_mssql_server"#).unwrap();
    static ref AZURE_SQL_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref AZURE_SQL_MIN_TLS_LOW: Regex = Regex::new(r#"(?i)minimum_tls_version\s*=\s*["']1\.[01]["']"#).unwrap();
    static ref AZURE_POSTGRES_NO_SSL: Regex = Regex::new(r#"(?i)ssl_enforcement_enabled\s*=\s*false"#).unwrap();
    static ref AZURE_POSTGRES_NO_GEO_BACKUP: Regex = Regex::new(r#"(?i)geo_redundant_backup_enabled\s*=\s*false"#).unwrap();
    static ref AZURE_MYSQL_NO_SSL: Regex = Regex::new(r#"(?i)ssl_enforcement_enabled\s*=\s*false"#).unwrap();
    static ref AZURE_COSMOSDB_NO_CMEK: Regex = Regex::new(r#"(?i)azurerm_cosmosdb_account"#).unwrap();
    static ref AZURE_COSMOSDB_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();

    // AKS patterns
    static ref AKS_NO_RBAC: Regex = Regex::new(r#"(?i)role_based_access_control_enabled\s*=\s*false"#).unwrap();
    static ref AKS_NO_AZURE_POLICY: Regex = Regex::new(r#"(?i)azure_policy_enabled\s*=\s*false"#).unwrap();
    static ref AKS_NO_PRIVATE_CLUSTER: Regex = Regex::new(r#"(?i)private_cluster_enabled\s*=\s*false"#).unwrap();
    static ref AKS_NETWORK_POLICY_NONE: Regex = Regex::new(r#"(?i)network_policy\s*=\s*["']none["']"#).unwrap();
    static ref AKS_NO_DISK_ENCRYPTION: Regex = Regex::new(r#"(?i)azurerm_kubernetes_cluster"#).unwrap();
    static ref AKS_LOCAL_ACCOUNT_ENABLED: Regex = Regex::new(r#"(?i)local_account_disabled\s*=\s*false"#).unwrap();
    static ref AKS_HTTP_APPLICATION_ROUTING: Regex = Regex::new(r#"(?i)http_application_routing_enabled\s*=\s*true"#).unwrap();
    static ref AKS_NO_MANAGED_IDENTITY: Regex = Regex::new(r#"(?i)azurerm_kubernetes_cluster"#).unwrap();
    static ref AKS_OUTDATED_VERSION: Regex = Regex::new(r#"(?i)kubernetes_version\s*=\s*["']1\.(2[0-6]|1[0-9]|[0-9])["']"#).unwrap();
    static ref AKS_NO_OMS_AGENT: Regex = Regex::new(r#"(?i)azurerm_kubernetes_cluster"#).unwrap();

    // Key Vault patterns
    static ref KV_SOFT_DELETE_DISABLED: Regex = Regex::new(r#"(?i)soft_delete_retention_days\s*=\s*0"#).unwrap();
    static ref KV_PURGE_PROTECTION_DISABLED: Regex = Regex::new(r#"(?i)purge_protection_enabled\s*=\s*false"#).unwrap();
    static ref KV_NO_NETWORK_RULES: Regex = Regex::new(r#"(?i)azurerm_key_vault"#).unwrap();
    static ref KV_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref KV_NO_RBAC: Regex = Regex::new(r#"(?i)enable_rbac_authorization\s*=\s*false"#).unwrap();

    // VM/Compute patterns
    static ref VM_NO_DISK_ENCRYPTION: Regex = Regex::new(r#"(?i)azurerm_(?:windows|linux)_virtual_machine"#).unwrap();
    static ref VM_NO_MANAGED_IDENTITY: Regex = Regex::new(r#"(?i)azurerm_(?:windows|linux)_virtual_machine"#).unwrap();
    static ref VM_PASSWORD_AUTH: Regex = Regex::new(r#"(?i)disable_password_authentication\s*=\s*false"#).unwrap();
    static ref VM_BASIC_SKU: Regex = Regex::new(r#"(?i)sku\s*=\s*["']Basic["']"#).unwrap();
    static ref VM_PUBLIC_IP: Regex = Regex::new(r#"(?i)resource\s+"azurerm_public_ip""#).unwrap();
    static ref VMSS_AUTOMATIC_OS_UPGRADE_DISABLED: Regex = Regex::new(r#"(?i)disable_automatic_rollback\s*=\s*true"#).unwrap();

    // Network patterns
    static ref NSG_ALLOW_ALL_INBOUND: Regex = Regex::new(r#"(?i)source_address_prefix\s*=\s*["']\*["']"#).unwrap();
    static ref NSG_SSH_OPEN: Regex = Regex::new(r#"(?i)destination_port_range\s*=\s*["']22["']"#).unwrap();
    static ref NSG_RDP_OPEN: Regex = Regex::new(r#"(?i)destination_port_range\s*=\s*["']3389["']"#).unwrap();
    static ref VNET_NO_DDOS: Regex = Regex::new(r#"(?i)azurerm_virtual_network"#).unwrap();
    static ref SUBNET_NO_NSG: Regex = Regex::new(r#"(?i)azurerm_subnet"#).unwrap();
    static ref APP_GW_NO_WAF: Regex = Regex::new(r#"(?i)tier\s*=\s*["']Standard["']"#).unwrap();
    static ref APP_GW_WAF_DISABLED: Regex = Regex::new(r#"(?i)enabled\s*=\s*false"#).unwrap();

    // App Service patterns
    static ref APP_SERVICE_HTTP_ENABLED: Regex = Regex::new(r#"(?i)https_only\s*=\s*false"#).unwrap();
    static ref APP_SERVICE_AUTH_DISABLED: Regex = Regex::new(r#"(?i)azurerm_(?:windows|linux)_web_app"#).unwrap();
    static ref APP_SERVICE_NO_MANAGED_IDENTITY: Regex = Regex::new(r#"(?i)azurerm_(?:windows|linux)_web_app"#).unwrap();
    static ref APP_SERVICE_FTP_ENABLED: Regex = Regex::new(r#"(?i)ftps_state\s*=\s*["']AllAllowed["']"#).unwrap();
    static ref APP_SERVICE_MIN_TLS_LOW: Regex = Regex::new(r#"(?i)minimum_tls_version\s*=\s*["']1\.[01]["']"#).unwrap();
    static ref APP_SERVICE_REMOTE_DEBUG: Regex = Regex::new(r#"(?i)remote_debugging_enabled\s*=\s*true"#).unwrap();
    static ref APP_SERVICE_CLIENT_CERT_DISABLED: Regex = Regex::new(r#"(?i)client_certificate_enabled\s*=\s*false"#).unwrap();
    static ref APP_SERVICE_HTTP2_DISABLED: Regex = Regex::new(r#"(?i)http2_enabled\s*=\s*false"#).unwrap();
    static ref FUNCTION_HTTP_ENABLED: Regex = Regex::new(r#"(?i)https_only\s*=\s*false"#).unwrap();

    // Container patterns
    static ref ACR_NO_ADMIN: Regex = Regex::new(r#"(?i)admin_enabled\s*=\s*true"#).unwrap();
    static ref ACR_NO_QUARANTINE: Regex = Regex::new(r#"(?i)quarantine_policy_enabled\s*=\s*false"#).unwrap();
    static ref ACR_NO_CONTENT_TRUST: Regex = Regex::new(r#"(?i)enabled\s*=\s*false"#).unwrap();
    static ref ACR_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref ACI_PUBLIC_IP: Regex = Regex::new(r#"(?i)ip_address_type\s*=\s*["']Public["']"#).unwrap();

    // Monitoring patterns
    static ref MONITOR_NO_DIAG_SETTINGS: Regex = Regex::new(r#"resource\s+"azurerm_monitor_diagnostic_setting""#).unwrap();
    static ref LOG_ANALYTICS_INTERNET_QUERY: Regex = Regex::new(r#"(?i)internet_query_enabled\s*=\s*true"#).unwrap();
    static ref LOG_ANALYTICS_INTERNET_INGESTION: Regex = Regex::new(r#"(?i)internet_ingestion_enabled\s*=\s*true"#).unwrap();
    static ref SECURITY_CENTER_TIER_FREE: Regex = Regex::new(r#"(?i)tier\s*=\s*["']Free["']"#).unwrap();

    // Service Bus patterns
    static ref SERVICE_BUS_NO_CMEK: Regex = Regex::new(r#"(?i)azurerm_servicebus_namespace"#).unwrap();
    static ref SERVICE_BUS_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref SERVICE_BUS_LOCAL_AUTH: Regex = Regex::new(r#"(?i)local_auth_enabled\s*=\s*true"#).unwrap();

    // Event Hub patterns
    static ref EVENT_HUB_NO_CMEK: Regex = Regex::new(r#"(?i)azurerm_eventhub_namespace"#).unwrap();
    static ref EVENT_HUB_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();

    // Redis patterns
    static ref REDIS_NO_TLS: Regex = Regex::new(r#"(?i)enable_non_ssl_port\s*=\s*true"#).unwrap();
    static ref REDIS_NO_FIREWALL: Regex = Regex::new(r#"(?i)azurerm_redis_cache"#).unwrap();
    static ref REDIS_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref REDIS_NO_PATCH_SCHEDULE: Regex = Regex::new(r#"(?i)azurerm_redis_cache"#).unwrap();

    // Synapse patterns
    static ref SYNAPSE_NO_AAD_ADMIN: Regex = Regex::new(r#"(?i)azurerm_synapse_workspace"#).unwrap();
    static ref SYNAPSE_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref SYNAPSE_NO_MANAGED_VNET: Regex = Regex::new(r#"(?i)managed_virtual_network_enabled\s*=\s*false"#).unwrap();

    // Batch patterns
    static ref BATCH_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_access_enabled\s*=\s*true"#).unwrap();
    static ref BATCH_NO_ENCRYPTION: Regex = Regex::new(r#"(?i)key_vault_key_id"#).unwrap();

    // Data Factory patterns
    static ref DATA_FACTORY_PUBLIC_NETWORK: Regex = Regex::new(r#"(?i)public_network_enabled\s*=\s*true"#).unwrap();
    static ref DATA_FACTORY_NO_MANAGED_IDENTITY: Regex = Regex::new(r#"(?i)azurerm_data_factory"#).unwrap();
}

// ============================================================================
// Rule Implementations
// ============================================================================

macro_rules! impl_azure_rule {
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
            fn providers(&self) -> &[IacCloudProvider] { &[IacCloudProvider::Azure] }
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

// Storage Account Rules
impl_azure_rule!(AzureStorageHttpRule, "AZURE_ST_001", "Azure Storage HTTP Enabled",
    "Azure Storage account allows HTTP traffic instead of requiring HTTPS",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set enable_https_traffic_only = true",
    "https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
    AZURE_STORAGE_HTTP_ENABLED, IacResourceType::AzureStorageAccount,
    "Storage account allows unencrypted HTTP traffic");

impl_azure_rule!(AzureStorageTls10Rule, "AZURE_ST_002", "Azure Storage TLS 1.0",
    "Azure Storage account uses TLS 1.0 which has known vulnerabilities",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set min_tls_version = 'TLS1_2'",
    "https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
    AZURE_STORAGE_NO_MIN_TLS, IacResourceType::AzureStorageAccount,
    "Storage account allows TLS 1.0");

impl_azure_rule!(AzureStorageTls11Rule, "AZURE_ST_003", "Azure Storage TLS 1.1",
    "Azure Storage account uses TLS 1.1 which is deprecated",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set min_tls_version = 'TLS1_2'",
    "https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
    AZURE_STORAGE_TLS11, IacResourceType::AzureStorageAccount,
    "Storage account allows TLS 1.1");

impl_azure_rule!(AzureStoragePublicNetworkRule, "AZURE_ST_004", "Azure Storage Public Network Access",
    "Azure Storage account allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false and use private endpoints",
    "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security",
    AZURE_STORAGE_PUBLIC_NETWORK, IacResourceType::AzureStorageAccount,
    "Storage account has public network access enabled");

impl_azure_rule!(AzureStorageBlobPublicRule, "AZURE_ST_005", "Azure Storage Blob Public Access",
    "Azure Storage account allows public access to blobs",
    IacSeverity::High, IacFindingCategory::PublicStorage,
    "Set allow_nested_items_to_be_public = false",
    "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure",
    AZURE_STORAGE_BLOB_PUBLIC, IacResourceType::AzureStorageAccount,
    "Storage account allows public blob access");

impl_azure_rule!(AzureStorageSharedKeyRule, "AZURE_ST_006", "Azure Storage Shared Key Access",
    "Azure Storage account has shared key access enabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set shared_access_key_enabled = false and use Azure AD authentication",
    "https://docs.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent",
    AZURE_STORAGE_SHARED_KEY_ENABLED, IacResourceType::AzureStorageAccount,
    "Storage account has shared key access enabled");

impl_azure_rule!(AzureStorageInfraEncryptionRule, "AZURE_ST_007", "Azure Storage Infrastructure Encryption Disabled",
    "Azure Storage account infrastructure encryption is disabled",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set infrastructure_encryption_enabled = true for double encryption",
    "https://docs.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable",
    AZURE_STORAGE_INFRASTRUCTURE_ENCRYPTION_DISABLED, IacResourceType::AzureStorageAccount,
    "Storage infrastructure encryption is disabled");

// SQL Rules
impl_azure_rule!(AzureSqlPublicNetworkRule, "AZURE_SQL_001", "Azure SQL Public Network Access",
    "Azure SQL Server allows public network access",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false and use private endpoints",
    "https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture",
    AZURE_SQL_PUBLIC_NETWORK, IacResourceType::AzureSqlServer,
    "SQL Server has public network access enabled");

impl_azure_rule!(AzureSqlTdeDisabledRule, "AZURE_SQL_002", "Azure SQL TDE Disabled",
    "Azure SQL transparent data encryption is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set transparent_data_encryption_enabled = true",
    "https://docs.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview",
    AZURE_SQL_NO_TDE, IacResourceType::AzureSqlServer,
    "SQL transparent data encryption is disabled");

impl_azure_rule!(AzureSqlMinTlsRule, "AZURE_SQL_003", "Azure SQL Minimum TLS Version Low",
    "Azure SQL Server minimum TLS version is below 1.2",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set minimum_tls_version = '1.2'",
    "https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings",
    AZURE_SQL_MIN_TLS_LOW, IacResourceType::AzureSqlServer,
    "SQL Server minimum TLS version is too low");

impl_azure_rule!(AzurePostgresNoSslRule, "AZURE_PG_001", "Azure PostgreSQL SSL Disabled",
    "Azure PostgreSQL SSL enforcement is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set ssl_enforcement_enabled = true",
    "https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security",
    AZURE_POSTGRES_NO_SSL, IacResourceType::AzureSqlServer,
    "PostgreSQL SSL enforcement is disabled");

impl_azure_rule!(AzurePostgresNoGeoBackupRule, "AZURE_PG_002", "Azure PostgreSQL Geo-Backup Disabled",
    "Azure PostgreSQL geo-redundant backup is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set geo_redundant_backup_enabled = true",
    "https://docs.microsoft.com/en-us/azure/postgresql/concepts-backup",
    AZURE_POSTGRES_NO_GEO_BACKUP, IacResourceType::AzureSqlServer,
    "PostgreSQL geo-redundant backup is disabled");

impl_azure_rule!(AzureMysqlNoSslRule, "AZURE_MY_001", "Azure MySQL SSL Disabled",
    "Azure MySQL SSL enforcement is disabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set ssl_enforcement_enabled = true",
    "https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security",
    AZURE_MYSQL_NO_SSL, IacResourceType::AzureSqlServer,
    "MySQL SSL enforcement is disabled");

impl_azure_rule!(AzureCosmosDbPublicRule, "AZURE_COSMOS_001", "Azure CosmosDB Public Network Access",
    "Azure CosmosDB allows public network access",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints",
    AZURE_COSMOSDB_PUBLIC_NETWORK, IacResourceType::AzureCosmosDb,
    "CosmosDB has public network access enabled");

// AKS Rules
impl_azure_rule!(AzureAksNoRbacRule, "AZURE_AKS_001", "AKS RBAC Disabled",
    "Azure Kubernetes Service has RBAC disabled",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Set role_based_access_control_enabled = true",
    "https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
    AKS_NO_RBAC, IacResourceType::AzureAks,
    "AKS RBAC is disabled");

impl_azure_rule!(AzureAksNoPrivateClusterRule, "AZURE_AKS_002", "AKS Not Private Cluster",
    "Azure Kubernetes Service is not configured as private cluster",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set private_cluster_enabled = true",
    "https://docs.microsoft.com/en-us/azure/aks/private-clusters",
    AKS_NO_PRIVATE_CLUSTER, IacResourceType::AzureAks,
    "AKS is not a private cluster");

impl_azure_rule!(AzureAksLocalAccountRule, "AZURE_AKS_003", "AKS Local Account Enabled",
    "Azure Kubernetes Service has local accounts enabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set local_account_disabled = true",
    "https://docs.microsoft.com/en-us/azure/aks/managed-aad",
    AKS_LOCAL_ACCOUNT_ENABLED, IacResourceType::AzureAks,
    "AKS local accounts are enabled");

impl_azure_rule!(AzureAksHttpRoutingRule, "AZURE_AKS_004", "AKS HTTP Application Routing Enabled",
    "Azure Kubernetes Service HTTP application routing is enabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set http_application_routing_enabled = false (use ingress controller instead)",
    "https://docs.microsoft.com/en-us/azure/aks/http-application-routing",
    AKS_HTTP_APPLICATION_ROUTING, IacResourceType::AzureAks,
    "AKS HTTP application routing is enabled");

impl_azure_rule!(AzureAksOutdatedVersionRule, "AZURE_AKS_005", "AKS Outdated Kubernetes Version",
    "Azure Kubernetes Service is running an outdated Kubernetes version",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Upgrade to a supported Kubernetes version (1.27+)",
    "https://docs.microsoft.com/en-us/azure/aks/supported-kubernetes-versions",
    AKS_OUTDATED_VERSION, IacResourceType::AzureAks,
    "AKS running outdated Kubernetes version");

// Key Vault Rules
impl_azure_rule!(AzureKvPurgeProtectionRule, "AZURE_KV_001", "Key Vault Purge Protection Disabled",
    "Azure Key Vault purge protection is disabled",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Set purge_protection_enabled = true",
    "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
    KV_PURGE_PROTECTION_DISABLED, IacResourceType::AzureKeyVault,
    "Key Vault purge protection is disabled");

impl_azure_rule!(AzureKvPublicNetworkRule, "AZURE_KV_002", "Key Vault Public Network Access",
    "Azure Key Vault allows public network access",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/key-vault/general/overview-vnet-service-endpoints",
    KV_PUBLIC_NETWORK, IacResourceType::AzureKeyVault,
    "Key Vault has public network access enabled");

impl_azure_rule!(AzureKvNoRbacRule, "AZURE_KV_003", "Key Vault RBAC Not Enabled",
    "Azure Key Vault is not using Azure RBAC for authorization",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set enable_rbac_authorization = true",
    "https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide",
    KV_NO_RBAC, IacResourceType::AzureKeyVault,
    "Key Vault not using RBAC authorization");

// VM Rules
impl_azure_rule!(AzureVmPasswordAuthRule, "AZURE_VM_001", "Azure Linux VM Password Authentication",
    "Azure Linux VM has password authentication enabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set disable_password_authentication = true and use SSH keys",
    "https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed",
    VM_PASSWORD_AUTH, IacResourceType::AzureVirtualMachine,
    "Linux VM password authentication is enabled");

impl_azure_rule!(AzureVmBasicSkuRule, "AZURE_VM_002", "Azure VM Basic SKU",
    "Azure VM is using Basic SKU which lacks security features",
    IacSeverity::Medium, IacFindingCategory::DataProtection,
    "Use Standard or Premium SKU for enhanced security",
    "https://docs.microsoft.com/en-us/azure/virtual-machines/sizes",
    VM_BASIC_SKU, IacResourceType::AzureVirtualMachine,
    "VM using Basic SKU");

// Network Rules
impl_azure_rule!(AzureNsgSshOpenRule, "AZURE_NSG_001", "NSG SSH Open to Internet",
    "Network Security Group allows SSH from any source",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Restrict source_address_prefix to specific IP ranges or use Azure Bastion",
    "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
    NSG_SSH_OPEN, IacResourceType::AzureNetworkSecurityGroup,
    "NSG allows SSH from anywhere");

impl_azure_rule!(AzureNsgRdpOpenRule, "AZURE_NSG_002", "NSG RDP Open to Internet",
    "Network Security Group allows RDP from any source",
    IacSeverity::Critical, IacFindingCategory::NetworkExposure,
    "Restrict source_address_prefix to specific IP ranges or use Azure Bastion",
    "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview",
    NSG_RDP_OPEN, IacResourceType::AzureNetworkSecurityGroup,
    "NSG allows RDP from anywhere");

// App Service Rules
impl_azure_rule!(AzureAppServiceHttpRule, "AZURE_APP_001", "App Service HTTP Enabled",
    "Azure App Service allows HTTP traffic",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set https_only = true",
    "https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings",
    APP_SERVICE_HTTP_ENABLED, IacResourceType::AzureAppService,
    "App Service allows HTTP traffic");

impl_azure_rule!(AzureAppServiceFtpRule, "AZURE_APP_002", "App Service FTP Enabled",
    "Azure App Service allows FTP access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set ftps_state = 'Disabled' or 'FtpsOnly'",
    "https://docs.microsoft.com/en-us/azure/app-service/deploy-ftp",
    APP_SERVICE_FTP_ENABLED, IacResourceType::AzureAppService,
    "App Service allows FTP access");

impl_azure_rule!(AzureAppServiceTlsRule, "AZURE_APP_003", "App Service TLS Version Low",
    "Azure App Service minimum TLS version is below 1.2",
    IacSeverity::Medium, IacFindingCategory::MissingEncryption,
    "Set minimum_tls_version = '1.2'",
    "https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings",
    APP_SERVICE_MIN_TLS_LOW, IacResourceType::AzureAppService,
    "App Service minimum TLS version is too low");

impl_azure_rule!(AzureAppServiceRemoteDebugRule, "AZURE_APP_004", "App Service Remote Debugging Enabled",
    "Azure App Service remote debugging is enabled",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set remote_debugging_enabled = false",
    "https://docs.microsoft.com/en-us/azure/app-service/troubleshoot-dotnet-visual-studio",
    APP_SERVICE_REMOTE_DEBUG, IacResourceType::AzureAppService,
    "App Service remote debugging is enabled");

impl_azure_rule!(AzureAppServiceClientCertRule, "AZURE_APP_005", "App Service Client Certificates Disabled",
    "Azure App Service client certificates are disabled",
    IacSeverity::Low, IacFindingCategory::IamMisconfiguration,
    "Set client_certificate_enabled = true for mutual TLS",
    "https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth",
    APP_SERVICE_CLIENT_CERT_DISABLED, IacResourceType::AzureAppService,
    "App Service client certificates disabled");

// Container Rules
impl_azure_rule!(AzureAcrAdminRule, "AZURE_ACR_001", "ACR Admin Account Enabled",
    "Azure Container Registry admin account is enabled",
    IacSeverity::High, IacFindingCategory::IamMisconfiguration,
    "Set admin_enabled = false and use Azure AD authentication",
    "https://docs.microsoft.com/en-us/azure/container-registry/container-registry-authentication",
    ACR_NO_ADMIN, IacResourceType::AzureContainerRegistry,
    "ACR admin account is enabled");

impl_azure_rule!(AzureAcrPublicNetworkRule, "AZURE_ACR_002", "ACR Public Network Access",
    "Azure Container Registry allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/container-registry/container-registry-access-selected-networks",
    ACR_PUBLIC_NETWORK, IacResourceType::AzureContainerRegistry,
    "ACR has public network access enabled");

impl_azure_rule!(AzureAciPublicIpRule, "AZURE_ACI_001", "ACI Public IP",
    "Azure Container Instance has public IP address",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set ip_address_type = 'Private' and deploy to VNet",
    "https://docs.microsoft.com/en-us/azure/container-instances/container-instances-vnet",
    ACI_PUBLIC_IP, IacResourceType::AzureContainerInstance,
    "Container Instance has public IP");

// Redis Rules
impl_azure_rule!(AzureRedisNoTlsRule, "AZURE_REDIS_001", "Azure Redis Non-SSL Port Enabled",
    "Azure Redis Cache has non-SSL port enabled",
    IacSeverity::High, IacFindingCategory::MissingEncryption,
    "Set enable_non_ssl_port = false",
    "https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-configure",
    REDIS_NO_TLS, IacResourceType::AzureRedis,
    "Redis non-SSL port is enabled");

impl_azure_rule!(AzureRedisPublicNetworkRule, "AZURE_REDIS_002", "Azure Redis Public Network Access",
    "Azure Redis Cache allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/azure-cache-for-redis/cache-private-link",
    REDIS_PUBLIC_NETWORK, IacResourceType::AzureRedis,
    "Redis has public network access enabled");

// Service Bus Rules
impl_azure_rule!(AzureServiceBusPublicNetworkRule, "AZURE_SB_001", "Service Bus Public Network Access",
    "Azure Service Bus allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/service-bus-messaging/private-link-service",
    SERVICE_BUS_PUBLIC_NETWORK, IacResourceType::AzureServiceBus,
    "Service Bus has public network access enabled");

impl_azure_rule!(AzureServiceBusLocalAuthRule, "AZURE_SB_002", "Service Bus Local Auth Enabled",
    "Azure Service Bus local authentication is enabled",
    IacSeverity::Medium, IacFindingCategory::IamMisconfiguration,
    "Set local_auth_enabled = false and use Azure AD authentication",
    "https://docs.microsoft.com/en-us/azure/service-bus-messaging/service-bus-authentication-and-authorization",
    SERVICE_BUS_LOCAL_AUTH, IacResourceType::AzureServiceBus,
    "Service Bus local auth is enabled");

// Event Hub Rules
impl_azure_rule!(AzureEventHubPublicNetworkRule, "AZURE_EH_001", "Event Hub Public Network Access",
    "Azure Event Hub allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/event-hubs/private-link-service",
    EVENT_HUB_PUBLIC_NETWORK, IacResourceType::AzureEventHub,
    "Event Hub has public network access enabled");

// Synapse Rules
impl_azure_rule!(AzureSynapsePublicNetworkRule, "AZURE_SYN_001", "Synapse Public Network Access",
    "Azure Synapse allows public network access",
    IacSeverity::High, IacFindingCategory::NetworkExposure,
    "Set public_network_access_enabled = false",
    "https://docs.microsoft.com/en-us/azure/synapse-analytics/security/connectivity-settings",
    SYNAPSE_PUBLIC_NETWORK, IacResourceType::AzureSynapse,
    "Synapse has public network access enabled");

impl_azure_rule!(AzureSynapseNoManagedVnetRule, "AZURE_SYN_002", "Synapse Managed VNet Disabled",
    "Azure Synapse managed virtual network is disabled",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set managed_virtual_network_enabled = true",
    "https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet",
    SYNAPSE_NO_MANAGED_VNET, IacResourceType::AzureSynapse,
    "Synapse managed VNet is disabled");

// Data Factory Rules
impl_azure_rule!(AzureDataFactoryPublicNetworkRule, "AZURE_ADF_001", "Data Factory Public Network Access",
    "Azure Data Factory allows public network access",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set public_network_enabled = false",
    "https://docs.microsoft.com/en-us/azure/data-factory/data-factory-private-link",
    DATA_FACTORY_PUBLIC_NETWORK, IacResourceType::AzureDataFactory,
    "Data Factory has public network access enabled");

// Security Center Rules
impl_azure_rule!(AzureSecurityCenterFreeTierRule, "AZURE_SC_001", "Security Center Free Tier",
    "Azure Security Center is using free tier",
    IacSeverity::Medium, IacFindingCategory::MissingLogging,
    "Set tier = 'Standard' for advanced threat protection",
    "https://docs.microsoft.com/en-us/azure/defender-for-cloud/enhanced-security-features-overview",
    SECURITY_CENTER_TIER_FREE, IacResourceType::AzureSecurityCenter,
    "Security Center using free tier");

// Monitoring Rules
impl_azure_rule!(AzureLogAnalyticsInternetQueryRule, "AZURE_LA_001", "Log Analytics Internet Query Enabled",
    "Azure Log Analytics allows queries from public internet",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set internet_query_enabled = false",
    "https://docs.microsoft.com/en-us/azure/azure-monitor/logs/private-link-configure",
    LOG_ANALYTICS_INTERNET_QUERY, IacResourceType::AzureLogAnalytics,
    "Log Analytics allows internet queries");

impl_azure_rule!(AzureLogAnalyticsInternetIngestionRule, "AZURE_LA_002", "Log Analytics Internet Ingestion Enabled",
    "Azure Log Analytics allows data ingestion from public internet",
    IacSeverity::Medium, IacFindingCategory::NetworkExposure,
    "Set internet_ingestion_enabled = false",
    "https://docs.microsoft.com/en-us/azure/azure-monitor/logs/private-link-configure",
    LOG_ANALYTICS_INTERNET_INGESTION, IacResourceType::AzureLogAnalytics,
    "Log Analytics allows internet ingestion");

/// Get all Azure rules
pub fn get_azure_rules() -> Vec<Box<dyn RuleMatcher>> {
    vec![
        // Storage Rules
        Box::new(AzureStorageHttpRule),
        Box::new(AzureStorageTls10Rule),
        Box::new(AzureStorageTls11Rule),
        Box::new(AzureStoragePublicNetworkRule),
        Box::new(AzureStorageBlobPublicRule),
        Box::new(AzureStorageSharedKeyRule),
        Box::new(AzureStorageInfraEncryptionRule),
        // SQL Rules
        Box::new(AzureSqlPublicNetworkRule),
        Box::new(AzureSqlTdeDisabledRule),
        Box::new(AzureSqlMinTlsRule),
        Box::new(AzurePostgresNoSslRule),
        Box::new(AzurePostgresNoGeoBackupRule),
        Box::new(AzureMysqlNoSslRule),
        Box::new(AzureCosmosDbPublicRule),
        // AKS Rules
        Box::new(AzureAksNoRbacRule),
        Box::new(AzureAksNoPrivateClusterRule),
        Box::new(AzureAksLocalAccountRule),
        Box::new(AzureAksHttpRoutingRule),
        Box::new(AzureAksOutdatedVersionRule),
        // Key Vault Rules
        Box::new(AzureKvPurgeProtectionRule),
        Box::new(AzureKvPublicNetworkRule),
        Box::new(AzureKvNoRbacRule),
        // VM Rules
        Box::new(AzureVmPasswordAuthRule),
        Box::new(AzureVmBasicSkuRule),
        // Network Rules
        Box::new(AzureNsgSshOpenRule),
        Box::new(AzureNsgRdpOpenRule),
        // App Service Rules
        Box::new(AzureAppServiceHttpRule),
        Box::new(AzureAppServiceFtpRule),
        Box::new(AzureAppServiceTlsRule),
        Box::new(AzureAppServiceRemoteDebugRule),
        Box::new(AzureAppServiceClientCertRule),
        // Container Rules
        Box::new(AzureAcrAdminRule),
        Box::new(AzureAcrPublicNetworkRule),
        Box::new(AzureAciPublicIpRule),
        // Redis Rules
        Box::new(AzureRedisNoTlsRule),
        Box::new(AzureRedisPublicNetworkRule),
        // Service Bus Rules
        Box::new(AzureServiceBusPublicNetworkRule),
        Box::new(AzureServiceBusLocalAuthRule),
        // Event Hub Rules
        Box::new(AzureEventHubPublicNetworkRule),
        // Synapse Rules
        Box::new(AzureSynapsePublicNetworkRule),
        Box::new(AzureSynapseNoManagedVnetRule),
        // Data Factory Rules
        Box::new(AzureDataFactoryPublicNetworkRule),
        // Security Center Rules
        Box::new(AzureSecurityCenterFreeTierRule),
        // Monitoring Rules
        Box::new(AzureLogAnalyticsInternetQueryRule),
        Box::new(AzureLogAnalyticsInternetIngestionRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_rules_count() {
        let rules = get_azure_rules();
        assert!(rules.len() >= 40, "Expected at least 40 Azure rules, got {}", rules.len());
    }

    #[test]
    fn test_storage_http_detection() {
        let rule = AzureStorageHttpRule;
        let content = r#"
resource "azurerm_storage_account" "example" {
  name = "example"
  enable_https_traffic_only = false
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_aks_rbac_detection() {
        let rule = AzureAksNoRbacRule;
        let content = r#"
resource "azurerm_kubernetes_cluster" "example" {
  name = "example"
  role_based_access_control_enabled = false
}
"#;
        let matches = rule.check(content, "main.tf", IacPlatform::Terraform);
        assert!(!matches.is_empty());
    }
}
