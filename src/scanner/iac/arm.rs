//! Azure ARM (Azure Resource Manager) template analyzer
//!
//! This module parses Azure ARM templates and analyzes them for security issues.

use super::rules::{get_builtin_rules, RuleMatcher};
use super::types::*;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;

/// Azure ARM-specific scanner
pub struct ArmScanner {
    rules: Vec<Box<dyn RuleMatcher>>,
}

impl ArmScanner {
    pub fn new() -> Self {
        Self {
            rules: get_builtin_rules(),
        }
    }

    pub fn with_custom_rules(custom_rules: Vec<Box<dyn RuleMatcher>>) -> Self {
        let mut rules = get_builtin_rules();
        rules.extend(custom_rules);
        Self { rules }
    }

    /// Detect if content is an ARM template
    pub fn is_arm_template(content: &str, filename: &str) -> bool {
        let lower_filename = filename.to_lowercase();

        // Check common ARM file patterns
        if lower_filename.ends_with(".arm.json")
            || lower_filename.contains("azuredeploy")
            || lower_filename.contains("maintemplate")
        {
            return true;
        }

        // Try to parse as JSON
        if let Ok(json) = serde_json::from_str::<Value>(content) {
            return is_arm_template_json(&json);
        }

        false
    }

    /// Parse ARM template
    pub fn parse_template(content: &str) -> Result<Value> {
        serde_json::from_str(content).context("Failed to parse ARM template as JSON")
    }

    /// Parse resources from ARM template
    pub fn parse_resources(&self, template: &Value, file_id: &str) -> Vec<IacResource> {
        let mut resources = Vec::new();

        if let Some(resources_arr) = template.get("resources").and_then(|r| r.as_array()) {
            for resource in resources_arr {
                let resource_type = resource
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("Unknown");

                let name = resource
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unnamed");

                let iac_resource_type = map_arm_resource_type(resource_type);

                let properties = resource
                    .get("properties")
                    .cloned()
                    .unwrap_or(Value::Object(serde_json::Map::new()));

                let attributes = if let Value::Object(map) = properties {
                    map.into_iter().map(|(k, v)| (k, v)).collect()
                } else {
                    HashMap::new()
                };

                resources.push(IacResource {
                    id: uuid::Uuid::new_v4().to_string(),
                    file_id: file_id.to_string(),
                    resource_type: iac_resource_type,
                    resource_name: name.to_string(),
                    provider: IacCloudProvider::Azure,
                    line_start: 0,
                    line_end: 0,
                    attributes,
                });

                // Check for nested resources
                if let Some(nested) = resource.get("resources").and_then(|r| r.as_array()) {
                    for nested_resource in nested {
                        let nested_type = nested_resource
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("Unknown");

                        let nested_name = nested_resource
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unnamed");

                        let full_type = format!("{}/{}", resource_type, nested_type);
                        let iac_resource_type = map_arm_resource_type(&full_type);

                        let nested_props = nested_resource
                            .get("properties")
                            .cloned()
                            .unwrap_or(Value::Object(serde_json::Map::new()));

                        let nested_attrs = if let Value::Object(map) = nested_props {
                            map.into_iter().map(|(k, v)| (k, v)).collect()
                        } else {
                            HashMap::new()
                        };

                        resources.push(IacResource {
                            id: uuid::Uuid::new_v4().to_string(),
                            file_id: file_id.to_string(),
                            resource_type: iac_resource_type,
                            resource_name: format!("{}/{}", name, nested_name),
                            provider: IacCloudProvider::Azure,
                            line_start: 0,
                            line_end: 0,
                            attributes: nested_attrs,
                        });
                    }
                }
            }
        }

        resources
    }

    /// Scan ARM template for security issues
    pub fn scan(
        &self,
        content: &str,
        filename: &str,
        scan_id: &str,
        file_id: &str,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        // Run text-based rules
        for rule in &self.rules {
            if !rule.platforms().contains(&IacPlatform::AzureArm) {
                continue;
            }

            let matches = rule.check(content, filename, IacPlatform::AzureArm);

            for rule_match in matches {
                let finding = IacFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    scan_id: scan_id.to_string(),
                    file_id: file_id.to_string(),
                    rule_id: rule.id().to_string(),
                    severity: rule.severity(),
                    category: rule.category(),
                    title: rule.name().to_string(),
                    description: rule_match
                        .message
                        .unwrap_or_else(|| rule.description().to_string()),
                    resource_type: rule_match.resource_type,
                    resource_name: rule_match.resource_name,
                    line_start: rule_match.line_start,
                    line_end: rule_match.line_end,
                    code_snippet: Some(rule_match.code_snippet),
                    remediation: rule.remediation().to_string(),
                    documentation_url: rule.documentation_url().map(String::from),
                    compliance_mappings: rule.compliance_mappings().to_vec(),
                    status: IacFindingStatus::Open,
                    suppressed: false,
                    suppression_reason: None,
                    created_at: chrono::Utc::now(),
                };
                findings.push(finding);
            }
        }

        // Run structure-based checks
        if let Ok(template) = Self::parse_template(content) {
            findings.extend(self.check_template_structure(&template, scan_id, file_id));
        }

        findings
    }

    /// Check ARM template structure for issues
    fn check_template_structure(
        &self,
        template: &Value,
        scan_id: &str,
        file_id: &str,
    ) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        if let Some(resources) = template.get("resources").and_then(|r| r.as_array()) {
            for resource in resources {
                let resource_type = resource
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                let name = resource
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unnamed");

                // Check Storage Account
                if resource_type == "Microsoft.Storage/storageAccounts" {
                    findings.extend(check_storage_account(resource, name, scan_id, file_id));
                }

                // Check SQL Server
                if resource_type == "Microsoft.Sql/servers" {
                    findings.extend(check_sql_server(resource, name, scan_id, file_id));
                }

                // Check Network Security Group
                if resource_type == "Microsoft.Network/networkSecurityGroups" {
                    findings.extend(check_nsg(resource, name, scan_id, file_id));
                }

                // Check Key Vault
                if resource_type == "Microsoft.KeyVault/vaults" {
                    findings.extend(check_key_vault(resource, name, scan_id, file_id));
                }

                // Check Virtual Machine
                if resource_type == "Microsoft.Compute/virtualMachines" {
                    findings.extend(check_virtual_machine(resource, name, scan_id, file_id));
                }

                // Check App Service
                if resource_type == "Microsoft.Web/sites" {
                    findings.extend(check_app_service(resource, name, scan_id, file_id));
                }

                // Check Cosmos DB
                if resource_type == "Microsoft.DocumentDB/databaseAccounts" {
                    findings.extend(check_cosmos_db(resource, name, scan_id, file_id));
                }

                // Check AKS
                if resource_type == "Microsoft.ContainerService/managedClusters" {
                    findings.extend(check_aks(resource, name, scan_id, file_id));
                }
            }
        }

        findings
    }

    /// Analyze a single ARM template file
    pub fn analyze_file(&self, content: &str, filename: &str) -> Result<AnalyzeFileResponse> {
        let file_id = uuid::Uuid::new_v4().to_string();
        let scan_id = uuid::Uuid::new_v4().to_string();

        let template = Self::parse_template(content)?;
        let resources = self.parse_resources(&template, &file_id);
        let findings = self.scan(content, filename, &scan_id, &file_id);

        let line_count = content.lines().count() as i32;

        let mut findings_by_severity: HashMap<String, i32> = HashMap::new();
        for finding in &findings {
            *findings_by_severity
                .entry(finding.severity.to_string())
                .or_insert(0) += 1;
        }

        Ok(AnalyzeFileResponse {
            platform: IacPlatform::AzureArm,
            provider: IacCloudProvider::Azure,
            resources,
            findings,
            summary: FileSummary {
                line_count,
                resource_count: 0,
                finding_count: 0,
                findings_by_severity,
            },
        })
    }
}

impl Default for ArmScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a JSON value looks like an ARM template
fn is_arm_template_json(value: &Value) -> bool {
    // Check for $schema with ARM template schema
    if let Some(schema) = value.get("$schema").and_then(|s| s.as_str()) {
        if schema.contains("deploymentTemplate.json") || schema.contains("subscriptionDeploymentTemplate.json") {
            return true;
        }
    }

    // Check for contentVersion (ARM template specific)
    if value.get("contentVersion").is_some() {
        // Check for resources with Microsoft.* types
        if let Some(resources) = value.get("resources").and_then(|r| r.as_array()) {
            for resource in resources {
                if let Some(rtype) = resource.get("type").and_then(|t| t.as_str()) {
                    if rtype.starts_with("Microsoft.") {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Map ARM resource type to IacResourceType
fn map_arm_resource_type(resource_type: &str) -> IacResourceType {
    match resource_type {
        "Microsoft.Storage/storageAccounts" => IacResourceType::AzureStorageAccount,
        "Microsoft.Storage/storageAccounts/blobServices/containers" => IacResourceType::AzureBlobContainer,
        "Microsoft.Authorization/roleAssignments" => IacResourceType::AzureRoleAssignment,
        "Microsoft.Compute/virtualMachines" => IacResourceType::AzureVirtualMachine,
        "Microsoft.Network/networkSecurityGroups" => IacResourceType::AzureNetworkSecurityGroup,
        "Microsoft.Sql/servers" => IacResourceType::AzureSqlServer,
        "Microsoft.Sql/servers/databases" => IacResourceType::AzureSqlDatabase,
        "Microsoft.KeyVault/vaults" => IacResourceType::AzureKeyVault,
        "Microsoft.Web/sites" => IacResourceType::AzureAppService,
        "Microsoft.Web/sites/functions" => IacResourceType::AzureFunctionApp,
        "Microsoft.DocumentDB/databaseAccounts" => IacResourceType::AzureCosmosDb,
        "Microsoft.ContainerService/managedClusters" => IacResourceType::AzureAks,
        "Microsoft.ContainerRegistry/registries" => IacResourceType::AzureContainerRegistry,
        _ => IacResourceType::Other(resource_type.to_string()),
    }
}

/// Check Storage Account for security issues
fn check_storage_account(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for public blob access
    let allow_blob_public = properties
        .get("allowBlobPublicAccess")
        .and_then(|a| a.as_bool())
        .unwrap_or(true); // Defaults to true if not specified

    if allow_blob_public {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC008",
            IacSeverity::Critical,
            IacFindingCategory::PublicStorage,
            "Azure Storage Public Blob Access",
            &format!("Storage account '{}' allows public blob access", name),
            Some(IacResourceType::AzureStorageAccount),
            Some(name.to_string()),
            "Set allowBlobPublicAccess to false to disable public blob access",
        ));
    }

    // Check for HTTPS only
    let supports_https_only = properties
        .get("supportsHttpsTrafficOnly")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    if !supports_https_only {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC019",
            IacSeverity::High,
            IacFindingCategory::WeakCryptography,
            "Azure Storage HTTP Access Allowed",
            &format!("Storage account '{}' allows unencrypted HTTP access", name),
            Some(IacResourceType::AzureStorageAccount),
            Some(name.to_string()),
            "Set supportsHttpsTrafficOnly to true to require HTTPS",
        ));
    }

    // Check for TLS version
    if let Some(min_tls) = properties.get("minimumTlsVersion").and_then(|t| t.as_str()) {
        if min_tls == "TLS1_0" || min_tls == "TLS1_1" {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC020",
                IacSeverity::Medium,
                IacFindingCategory::WeakCryptography,
                "Azure Storage Weak TLS Version",
                &format!("Storage account '{}' allows weak TLS version: {}", name, min_tls),
                Some(IacResourceType::AzureStorageAccount),
                Some(name.to_string()),
                "Set minimumTlsVersion to TLS1_2",
            ));
        }
    }

    // Check for encryption
    if let Some(encryption) = properties.get("encryption") {
        let services = encryption.get("services").unwrap_or(&Value::Null);

        // Check blob encryption
        if let Some(blob) = services.get("blob") {
            let enabled = blob.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
            if !enabled {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC021",
                    IacSeverity::High,
                    IacFindingCategory::MissingEncryption,
                    "Azure Storage Blob Encryption Disabled",
                    &format!("Storage account '{}' has blob encryption disabled", name),
                    Some(IacResourceType::AzureStorageAccount),
                    Some(name.to_string()),
                    "Enable blob encryption in the encryption.services.blob configuration",
                ));
            }
        }
    }

    findings
}

/// Check SQL Server for security issues
fn check_sql_server(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for Azure AD admin
    if properties.get("administrators").is_none() {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC022",
            IacSeverity::Medium,
            IacFindingCategory::IamMisconfiguration,
            "Azure SQL No Azure AD Admin",
            &format!("SQL Server '{}' does not have Azure AD administrator configured", name),
            Some(IacResourceType::AzureSqlServer),
            Some(name.to_string()),
            "Configure Azure AD administrator for the SQL server",
        ));
    }

    // Check for minimum TLS version
    if let Some(min_tls) = properties.get("minimalTlsVersion").and_then(|t| t.as_str()) {
        if min_tls == "1.0" || min_tls == "1.1" {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC023",
                IacSeverity::Medium,
                IacFindingCategory::WeakCryptography,
                "Azure SQL Weak TLS Version",
                &format!("SQL Server '{}' allows weak TLS version: {}", name, min_tls),
                Some(IacResourceType::AzureSqlServer),
                Some(name.to_string()),
                "Set minimalTlsVersion to 1.2",
            ));
        }
    }

    // Check nested firewall rules
    if let Some(resources) = resource.get("resources").and_then(|r| r.as_array()) {
        for nested in resources {
            let nested_type = nested.get("type").and_then(|t| t.as_str()).unwrap_or("");

            if nested_type == "firewallRules" {
                let fw_props = nested.get("properties").unwrap_or(&Value::Null);
                let start_ip = fw_props.get("startIpAddress").and_then(|s| s.as_str()).unwrap_or("");
                let end_ip = fw_props.get("endIpAddress").and_then(|e| e.as_str()).unwrap_or("");

                if start_ip == "0.0.0.0" && end_ip == "255.255.255.255" {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC009",
                        IacSeverity::Critical,
                        IacFindingCategory::NetworkExposure,
                        "Azure SQL Firewall Wide Open",
                        &format!("SQL Server '{}' has firewall rule allowing all IP addresses", name),
                        Some(IacResourceType::AzureSqlServer),
                        Some(name.to_string()),
                        "Restrict firewall rules to specific IP addresses or use private endpoints",
                    ));
                } else if start_ip == "0.0.0.0" && end_ip == "0.0.0.0" {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC024",
                        IacSeverity::Medium,
                        IacFindingCategory::NetworkExposure,
                        "Azure SQL Allow Azure Services",
                        &format!("SQL Server '{}' allows access from all Azure services", name),
                        Some(IacResourceType::AzureSqlServer),
                        Some(name.to_string()),
                        "Consider using private endpoints instead of allowing all Azure services",
                    ));
                }
            }
        }
    }

    findings
}

/// Check Network Security Group for security issues
fn check_nsg(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    if let Some(rules) = properties.get("securityRules").and_then(|r| r.as_array()) {
        for rule in rules {
            let rule_props = rule.get("properties").unwrap_or(&Value::Null);
            let direction = rule_props.get("direction").and_then(|d| d.as_str()).unwrap_or("");
            let access = rule_props.get("access").and_then(|a| a.as_str()).unwrap_or("");
            let source = rule_props.get("sourceAddressPrefix").and_then(|s| s.as_str()).unwrap_or("");

            if direction == "Inbound" && access == "Allow" && (source == "*" || source == "Internet") {
                let dest_port = rule_props.get("destinationPortRange").and_then(|p| p.as_str()).unwrap_or("");

                // Check for SSH
                if dest_port == "22" || dest_port == "*" {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC007",
                        IacSeverity::Critical,
                        IacFindingCategory::NetworkExposure,
                        "Azure NSG SSH Open to Internet",
                        &format!("NSG '{}' allows SSH (port 22) from Internet", name),
                        Some(IacResourceType::AzureNetworkSecurityGroup),
                        Some(name.to_string()),
                        "Restrict SSH access to specific IP addresses or use Azure Bastion",
                    ));
                }

                // Check for RDP
                if dest_port == "3389" || dest_port == "*" {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC007",
                        IacSeverity::Critical,
                        IacFindingCategory::NetworkExposure,
                        "Azure NSG RDP Open to Internet",
                        &format!("NSG '{}' allows RDP (port 3389) from Internet", name),
                        Some(IacResourceType::AzureNetworkSecurityGroup),
                        Some(name.to_string()),
                        "Restrict RDP access to specific IP addresses or use Azure Bastion",
                    ));
                }

                // General wide open rule
                if dest_port == "*" {
                    findings.push(create_finding(
                        scan_id,
                        file_id,
                        "IAC003",
                        IacSeverity::High,
                        IacFindingCategory::NetworkExposure,
                        "Azure NSG Wide Open",
                        &format!("NSG '{}' allows all ports from Internet", name),
                        Some(IacResourceType::AzureNetworkSecurityGroup),
                        Some(name.to_string()),
                        "Restrict inbound rules to specific ports required by your application",
                    ));
                }
            }
        }
    }

    findings
}

/// Check Key Vault for security issues
fn check_key_vault(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for soft delete
    let soft_delete = properties
        .get("enableSoftDelete")
        .and_then(|s| s.as_bool())
        .unwrap_or(true); // Default is now true

    if !soft_delete {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC025",
            IacSeverity::Medium,
            IacFindingCategory::BestPractice,
            "Azure Key Vault Soft Delete Disabled",
            &format!("Key Vault '{}' has soft delete disabled", name),
            Some(IacResourceType::AzureKeyVault),
            Some(name.to_string()),
            "Enable soft delete to protect against accidental deletion",
        ));
    }

    // Check for purge protection
    let purge_protection = properties
        .get("enablePurgeProtection")
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    if !purge_protection {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC026",
            IacSeverity::Low,
            IacFindingCategory::BestPractice,
            "Azure Key Vault Purge Protection Disabled",
            &format!("Key Vault '{}' does not have purge protection enabled", name),
            Some(IacResourceType::AzureKeyVault),
            Some(name.to_string()),
            "Enable purge protection to prevent permanent deletion during soft delete period",
        ));
    }

    // Check for RBAC authorization
    let enable_rbac = properties
        .get("enableRbacAuthorization")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);

    if !enable_rbac {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC027",
            IacSeverity::Low,
            IacFindingCategory::BestPractice,
            "Azure Key Vault Using Access Policies",
            &format!("Key Vault '{}' uses access policies instead of RBAC", name),
            Some(IacResourceType::AzureKeyVault),
            Some(name.to_string()),
            "Consider enabling RBAC authorization for better access control",
        ));
    }

    findings
}

/// Check Virtual Machine for security issues
fn check_virtual_machine(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check OS profile for password authentication
    if let Some(os_profile) = properties.get("osProfile") {
        // Linux specific
        if let Some(linux_config) = os_profile.get("linuxConfiguration") {
            let disable_password = linux_config
                .get("disablePasswordAuthentication")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);

            if !disable_password {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC028",
                    IacSeverity::Medium,
                    IacFindingCategory::InsecureDefault,
                    "Azure VM Password Authentication Enabled",
                    &format!("Virtual machine '{}' allows password authentication for SSH", name),
                    Some(IacResourceType::AzureVirtualMachine),
                    Some(name.to_string()),
                    "Set disablePasswordAuthentication to true and use SSH keys",
                ));
            }
        }

        // Check for admin username
        if let Some(admin_username) = os_profile.get("adminUsername").and_then(|u| u.as_str()) {
            let weak_usernames = ["admin", "administrator", "root", "user"];
            if weak_usernames.contains(&admin_username.to_lowercase().as_str()) {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC029",
                    IacSeverity::Medium,
                    IacFindingCategory::InsecureDefault,
                    "Azure VM Weak Admin Username",
                    &format!("Virtual machine '{}' uses common admin username: {}", name, admin_username),
                    Some(IacResourceType::AzureVirtualMachine),
                    Some(name.to_string()),
                    "Use a unique, non-standard admin username",
                ));
            }
        }
    }

    // Check for disk encryption
    if let Some(storage_profile) = properties.get("storageProfile") {
        if let Some(os_disk) = storage_profile.get("osDisk") {
            let encryption = os_disk.get("encryptionSettings");
            if encryption.is_none() {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC030",
                    IacSeverity::High,
                    IacFindingCategory::MissingEncryption,
                    "Azure VM OS Disk Not Encrypted",
                    &format!("Virtual machine '{}' OS disk does not have encryption configured", name),
                    Some(IacResourceType::AzureVirtualMachine),
                    Some(name.to_string()),
                    "Enable Azure Disk Encryption for the OS disk",
                ));
            }
        }
    }

    findings
}

/// Check App Service for security issues
fn check_app_service(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for HTTPS only
    let https_only = properties
        .get("httpsOnly")
        .and_then(|h| h.as_bool())
        .unwrap_or(false);

    if !https_only {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC031",
            IacSeverity::High,
            IacFindingCategory::WeakCryptography,
            "Azure App Service HTTP Allowed",
            &format!("App Service '{}' allows unencrypted HTTP traffic", name),
            Some(IacResourceType::AzureAppService),
            Some(name.to_string()),
            "Set httpsOnly to true to require HTTPS",
        ));
    }

    // Check for minimum TLS version
    if let Some(site_config) = properties.get("siteConfig") {
        if let Some(min_tls) = site_config.get("minTlsVersion").and_then(|t| t.as_str()) {
            if min_tls == "1.0" || min_tls == "1.1" {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC032",
                    IacSeverity::Medium,
                    IacFindingCategory::WeakCryptography,
                    "Azure App Service Weak TLS",
                    &format!("App Service '{}' allows weak TLS version: {}", name, min_tls),
                    Some(IacResourceType::AzureAppService),
                    Some(name.to_string()),
                    "Set minTlsVersion to 1.2",
                ));
            }
        }

        // Check for FTP state
        if let Some(ftp_state) = site_config.get("ftpsState").and_then(|f| f.as_str()) {
            if ftp_state == "AllAllowed" {
                findings.push(create_finding(
                    scan_id,
                    file_id,
                    "IAC033",
                    IacSeverity::High,
                    IacFindingCategory::InsecureDefault,
                    "Azure App Service FTP Allowed",
                    &format!("App Service '{}' allows unencrypted FTP", name),
                    Some(IacResourceType::AzureAppService),
                    Some(name.to_string()),
                    "Set ftpsState to FtpsOnly or Disabled",
                ));
            }
        }
    }

    findings
}

/// Check Cosmos DB for security issues
fn check_cosmos_db(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for public network access
    let public_access = properties
        .get("publicNetworkAccess")
        .and_then(|p| p.as_str())
        .unwrap_or("Enabled");

    if public_access == "Enabled" {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC034",
            IacSeverity::Medium,
            IacFindingCategory::NetworkExposure,
            "Azure Cosmos DB Public Access",
            &format!("Cosmos DB '{}' has public network access enabled", name),
            Some(IacResourceType::AzureCosmosDb),
            Some(name.to_string()),
            "Set publicNetworkAccess to Disabled and use private endpoints",
        ));
    }

    // Check for IP rules (firewall)
    let ip_rules = properties.get("ipRules").and_then(|r| r.as_array());
    if ip_rules.is_none() || ip_rules.map(|r| r.is_empty()).unwrap_or(true) {
        if public_access == "Enabled" {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC035",
                IacSeverity::High,
                IacFindingCategory::NetworkExposure,
                "Azure Cosmos DB No IP Firewall",
                &format!("Cosmos DB '{}' has no IP firewall rules configured", name),
                Some(IacResourceType::AzureCosmosDb),
                Some(name.to_string()),
                "Configure ipRules to restrict access to specific IP addresses",
            ));
        }
    }

    findings
}

/// Check AKS for security issues
fn check_aks(
    resource: &Value,
    name: &str,
    scan_id: &str,
    file_id: &str,
) -> Vec<IacFinding> {
    let mut findings = Vec::new();
    let properties = resource.get("properties").unwrap_or(&Value::Null);

    // Check for RBAC
    let enable_rbac = properties
        .get("enableRBAC")
        .and_then(|r| r.as_bool())
        .unwrap_or(true);

    if !enable_rbac {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC036",
            IacSeverity::High,
            IacFindingCategory::IamMisconfiguration,
            "Azure AKS RBAC Disabled",
            &format!("AKS cluster '{}' has RBAC disabled", name),
            Some(IacResourceType::AzureAks),
            Some(name.to_string()),
            "Set enableRBAC to true for proper access control",
        ));
    }

    // Check for Azure AD integration
    if let Some(aad_profile) = properties.get("aadProfile") {
        let managed = aad_profile.get("managed").and_then(|m| m.as_bool()).unwrap_or(false);
        if !managed {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC037",
                IacSeverity::Medium,
                IacFindingCategory::BestPractice,
                "Azure AKS Legacy AAD Integration",
                &format!("AKS cluster '{}' uses legacy Azure AD integration", name),
                Some(IacResourceType::AzureAks),
                Some(name.to_string()),
                "Use managed Azure AD integration by setting aadProfile.managed to true",
            ));
        }
    } else {
        findings.push(create_finding(
            scan_id,
            file_id,
            "IAC038",
            IacSeverity::Medium,
            IacFindingCategory::IamMisconfiguration,
            "Azure AKS No AAD Integration",
            &format!("AKS cluster '{}' does not have Azure AD integration", name),
            Some(IacResourceType::AzureAks),
            Some(name.to_string()),
            "Configure aadProfile for Azure AD integration",
        ));
    }

    // Check for network policy
    if let Some(network_profile) = properties.get("networkProfile") {
        let network_policy = network_profile.get("networkPolicy").and_then(|n| n.as_str());
        if network_policy.is_none() {
            findings.push(create_finding(
                scan_id,
                file_id,
                "IAC039",
                IacSeverity::Medium,
                IacFindingCategory::NetworkExposure,
                "Azure AKS No Network Policy",
                &format!("AKS cluster '{}' does not have network policy configured", name),
                Some(IacResourceType::AzureAks),
                Some(name.to_string()),
                "Configure networkPolicy (azure or calico) for pod network isolation",
            ));
        }
    }

    findings
}

/// Helper to create an IacFinding
fn create_finding(
    scan_id: &str,
    file_id: &str,
    rule_id: &str,
    severity: IacSeverity,
    category: IacFindingCategory,
    title: &str,
    description: &str,
    resource_type: Option<IacResourceType>,
    resource_name: Option<String>,
    remediation: &str,
) -> IacFinding {
    IacFinding {
        id: uuid::Uuid::new_v4().to_string(),
        scan_id: scan_id.to_string(),
        file_id: file_id.to_string(),
        rule_id: rule_id.to_string(),
        severity,
        category,
        title: title.to_string(),
        description: description.to_string(),
        resource_type,
        resource_name,
        line_start: 0,
        line_end: 0,
        code_snippet: None,
        remediation: remediation.to_string(),
        documentation_url: None,
        compliance_mappings: Vec::new(),
        status: IacFindingStatus::Open,
        suppressed: false,
        suppression_reason: None,
        created_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_arm_template() {
        let arm_content = r#"{
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": []
        }"#;
        assert!(ArmScanner::is_arm_template(arm_content, "template.json"));

        // Test with azuredeploy filename
        assert!(ArmScanner::is_arm_template("{}", "azuredeploy.json"));
    }

    #[test]
    fn test_parse_template() {
        let content = r#"{
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "mystorageaccount",
                    "properties": {}
                }
            ]
        }"#;

        let template = ArmScanner::parse_template(content).unwrap();
        assert!(template.get("resources").is_some());
    }

    #[test]
    fn test_scan_detects_public_storage() {
        let scanner = ArmScanner::new();

        let content = r#"{
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "name": "mystorageaccount",
                    "properties": {
                        "allowBlobPublicAccess": true
                    }
                }
            ]
        }"#;

        let findings = scanner.scan(content, "template.json", "scan-1", "file-1");
        let public_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::PublicStorage)
            .collect();

        assert!(!public_findings.is_empty(), "Should detect public storage");
    }

    #[test]
    fn test_scan_detects_nsg_issues() {
        let scanner = ArmScanner::new();

        let content = r#"{
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Network/networkSecurityGroups",
                    "name": "myNSG",
                    "properties": {
                        "securityRules": [
                            {
                                "name": "AllowSSH",
                                "properties": {
                                    "direction": "Inbound",
                                    "access": "Allow",
                                    "sourceAddressPrefix": "*",
                                    "destinationPortRange": "22"
                                }
                            }
                        ]
                    }
                }
            ]
        }"#;

        let findings = scanner.scan(content, "template.json", "scan-1", "file-1");
        let network_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == IacFindingCategory::NetworkExposure)
            .collect();

        assert!(!network_findings.is_empty(), "Should detect open SSH");
    }
}
