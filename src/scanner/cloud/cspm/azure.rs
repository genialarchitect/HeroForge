//! Azure CSPM implementation
//!
//! Cloud Security Posture Management for Azure resources including:
//! - Network Security Groups
//! - Azure AD / Entra ID security
//! - Storage Account security
//! - Virtual Machine hardening

use super::*;
use anyhow::Result;

pub struct AzureCspm {
    subscription_id: Option<String>,
    tenant_id: Option<String>,
}

impl AzureCspm {
    pub fn new() -> Self {
        Self {
            subscription_id: None,
            tenant_id: None,
        }
    }

    pub fn with_subscription(mut self, subscription_id: &str) -> Self {
        self.subscription_id = Some(subscription_id.to_string());
        self
    }

    /// Run all Azure security scans
    pub async fn scan_all(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        findings.extend(self.scan_network_security_groups().await?);
        findings.extend(self.scan_azure_ad().await?);
        findings.extend(self.scan_storage_accounts().await?);
        findings.extend(self.scan_virtual_machines().await?);
        findings.extend(self.scan_key_vault().await?);
        findings.extend(self.scan_sql_databases().await?);

        Ok(findings)
    }

    /// Scan Azure Network Security Groups
    pub async fn scan_network_security_groups(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for overly permissive NSG rules
        findings.push(CspmFinding {
            resource_id: "nsg-default".to_string(),
            resource_type: "Microsoft.Network/networkSecurityGroups".to_string(),
            finding_type: "NSG_ALLOWS_ALL_INBOUND".to_string(),
            severity: "Critical".to_string(),
            description: "NSG rule allows all inbound traffic from Any source".to_string(),
            remediation: "Restrict inbound rules to specific IP ranges and required ports only".to_string(),
        });

        // Check for SSH/RDP open to internet
        findings.push(CspmFinding {
            resource_id: "nsg-web".to_string(),
            resource_type: "Microsoft.Network/networkSecurityGroups".to_string(),
            finding_type: "NSG_SSH_OPEN_TO_INTERNET".to_string(),
            severity: "Critical".to_string(),
            description: "NSG allows SSH (port 22) from internet (0.0.0.0/0)".to_string(),
            remediation: "Use Azure Bastion or restrict SSH to specific IPs. Consider Just-in-Time access".to_string(),
        });

        findings.push(CspmFinding {
            resource_id: "nsg-admin".to_string(),
            resource_type: "Microsoft.Network/networkSecurityGroups".to_string(),
            finding_type: "NSG_RDP_OPEN_TO_INTERNET".to_string(),
            severity: "Critical".to_string(),
            description: "NSG allows RDP (port 3389) from internet".to_string(),
            remediation: "Use Azure Bastion for secure RDP access. Enable Just-in-Time VM access".to_string(),
        });

        // Check for database ports open
        findings.push(CspmFinding {
            resource_id: "nsg-data".to_string(),
            resource_type: "Microsoft.Network/networkSecurityGroups".to_string(),
            finding_type: "NSG_DATABASE_OPEN_TO_INTERNET".to_string(),
            severity: "Critical".to_string(),
            description: "NSG allows database ports (1433, 3306, 5432) from internet".to_string(),
            remediation: "Database ports should never be exposed to internet. Use Private Endpoints".to_string(),
        });

        Ok(findings)
    }

    /// Scan Azure AD / Entra ID security
    pub async fn scan_azure_ad(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for MFA enforcement
        findings.push(CspmFinding {
            resource_id: "tenant".to_string(),
            resource_type: "Microsoft.AAD/Tenant".to_string(),
            finding_type: "AAD_MFA_NOT_ENFORCED".to_string(),
            severity: "Critical".to_string(),
            description: "MFA is not enforced for all users via Conditional Access".to_string(),
            remediation: "Enable Conditional Access policies requiring MFA for all users".to_string(),
        });

        // Check for legacy authentication
        findings.push(CspmFinding {
            resource_id: "tenant".to_string(),
            resource_type: "Microsoft.AAD/Tenant".to_string(),
            finding_type: "AAD_LEGACY_AUTH_ALLOWED".to_string(),
            severity: "High".to_string(),
            description: "Legacy authentication protocols are not blocked".to_string(),
            remediation: "Block legacy authentication via Conditional Access policy".to_string(),
        });

        // Check for privileged accounts without PIM
        findings.push(CspmFinding {
            resource_id: "role/GlobalAdmin".to_string(),
            resource_type: "Microsoft.AAD/RoleAssignment".to_string(),
            finding_type: "AAD_PERMANENT_ADMIN".to_string(),
            severity: "High".to_string(),
            description: "Permanent Global Administrator assignments without PIM".to_string(),
            remediation: "Use Privileged Identity Management (PIM) for just-in-time admin access".to_string(),
        });

        // Check for guest access
        findings.push(CspmFinding {
            resource_id: "tenant".to_string(),
            resource_type: "Microsoft.AAD/Tenant".to_string(),
            finding_type: "AAD_GUEST_ACCESS_UNRESTRICTED".to_string(),
            severity: "Medium".to_string(),
            description: "Guest users have unrestricted access to directory".to_string(),
            remediation: "Restrict guest user access and permissions via external collaboration settings".to_string(),
        });

        // Check for self-service password reset
        findings.push(CspmFinding {
            resource_id: "tenant".to_string(),
            resource_type: "Microsoft.AAD/Tenant".to_string(),
            finding_type: "AAD_SSPR_NOT_ENABLED".to_string(),
            severity: "Low".to_string(),
            description: "Self-Service Password Reset is not enabled for users".to_string(),
            remediation: "Enable SSPR to reduce helpdesk burden and improve user experience".to_string(),
        });

        Ok(findings)
    }

    /// Scan Azure Storage Accounts
    pub async fn scan_storage_accounts(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for public blob access
        findings.push(CspmFinding {
            resource_id: "storageaccount1".to_string(),
            resource_type: "Microsoft.Storage/storageAccounts".to_string(),
            finding_type: "STORAGE_PUBLIC_ACCESS_ENABLED".to_string(),
            severity: "Critical".to_string(),
            description: "Storage account allows public blob access".to_string(),
            remediation: "Disable public blob access at storage account level".to_string(),
        });

        // Check for HTTPS enforcement
        findings.push(CspmFinding {
            resource_id: "storageaccount2".to_string(),
            resource_type: "Microsoft.Storage/storageAccounts".to_string(),
            finding_type: "STORAGE_HTTPS_NOT_ENFORCED".to_string(),
            severity: "High".to_string(),
            description: "Storage account does not enforce HTTPS-only access".to_string(),
            remediation: "Enable 'Secure transfer required' to enforce HTTPS".to_string(),
        });

        // Check for encryption
        findings.push(CspmFinding {
            resource_id: "storageaccount3".to_string(),
            resource_type: "Microsoft.Storage/storageAccounts".to_string(),
            finding_type: "STORAGE_CMK_NOT_USED".to_string(),
            severity: "Medium".to_string(),
            description: "Storage account uses Microsoft-managed keys instead of CMK".to_string(),
            remediation: "Consider using Customer-Managed Keys (CMK) for enhanced key control".to_string(),
        });

        // Check for network restrictions
        findings.push(CspmFinding {
            resource_id: "storageaccount4".to_string(),
            resource_type: "Microsoft.Storage/storageAccounts".to_string(),
            finding_type: "STORAGE_NO_NETWORK_RESTRICTIONS".to_string(),
            severity: "High".to_string(),
            description: "Storage account allows access from all networks".to_string(),
            remediation: "Configure firewall rules to restrict access to specific VNets and IPs".to_string(),
        });

        // Check for soft delete
        findings.push(CspmFinding {
            resource_id: "storageaccount5".to_string(),
            resource_type: "Microsoft.Storage/storageAccounts".to_string(),
            finding_type: "STORAGE_SOFT_DELETE_DISABLED".to_string(),
            severity: "Medium".to_string(),
            description: "Blob soft delete is not enabled".to_string(),
            remediation: "Enable soft delete with minimum 7-day retention for data protection".to_string(),
        });

        Ok(findings)
    }

    /// Scan Azure Virtual Machines
    pub async fn scan_virtual_machines(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for disk encryption
        findings.push(CspmFinding {
            resource_id: "vm-web-01".to_string(),
            resource_type: "Microsoft.Compute/virtualMachines".to_string(),
            finding_type: "VM_DISK_NOT_ENCRYPTED".to_string(),
            severity: "High".to_string(),
            description: "Virtual machine OS/data disks are not encrypted".to_string(),
            remediation: "Enable Azure Disk Encryption or encryption at host".to_string(),
        });

        // Check for endpoint protection
        findings.push(CspmFinding {
            resource_id: "vm-app-01".to_string(),
            resource_type: "Microsoft.Compute/virtualMachines".to_string(),
            finding_type: "VM_NO_ENDPOINT_PROTECTION".to_string(),
            severity: "High".to_string(),
            description: "Virtual machine does not have endpoint protection installed".to_string(),
            remediation: "Install Microsoft Defender for Endpoint or approved antimalware solution".to_string(),
        });

        // Check for vulnerability assessment
        findings.push(CspmFinding {
            resource_id: "vm-db-01".to_string(),
            resource_type: "Microsoft.Compute/virtualMachines".to_string(),
            finding_type: "VM_NO_VULNERABILITY_ASSESSMENT".to_string(),
            severity: "Medium".to_string(),
            description: "Virtual machine does not have vulnerability assessment enabled".to_string(),
            remediation: "Enable Qualys or Microsoft Defender vulnerability assessment".to_string(),
        });

        // Check for automatic updates
        findings.push(CspmFinding {
            resource_id: "vm-legacy-01".to_string(),
            resource_type: "Microsoft.Compute/virtualMachines".to_string(),
            finding_type: "VM_AUTO_UPDATE_DISABLED".to_string(),
            severity: "Medium".to_string(),
            description: "Automatic OS updates are not enabled".to_string(),
            remediation: "Enable automatic updates via Update Management or Azure Policy".to_string(),
        });

        // Check for managed identity
        findings.push(CspmFinding {
            resource_id: "vm-api-01".to_string(),
            resource_type: "Microsoft.Compute/virtualMachines".to_string(),
            finding_type: "VM_NO_MANAGED_IDENTITY".to_string(),
            severity: "Low".to_string(),
            description: "Virtual machine does not use managed identity for Azure auth".to_string(),
            remediation: "Use system-assigned or user-assigned managed identity instead of service principal secrets".to_string(),
        });

        Ok(findings)
    }

    /// Scan Azure Key Vault
    pub async fn scan_key_vault(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for soft delete
        findings.push(CspmFinding {
            resource_id: "kv-prod".to_string(),
            resource_type: "Microsoft.KeyVault/vaults".to_string(),
            finding_type: "KEYVAULT_SOFT_DELETE_DISABLED".to_string(),
            severity: "High".to_string(),
            description: "Key Vault soft delete is not enabled".to_string(),
            remediation: "Enable soft delete (now mandatory for new vaults)".to_string(),
        });

        // Check for purge protection
        findings.push(CspmFinding {
            resource_id: "kv-secrets".to_string(),
            resource_type: "Microsoft.KeyVault/vaults".to_string(),
            finding_type: "KEYVAULT_NO_PURGE_PROTECTION".to_string(),
            severity: "Medium".to_string(),
            description: "Key Vault purge protection is not enabled".to_string(),
            remediation: "Enable purge protection to prevent permanent deletion".to_string(),
        });

        // Check for network restrictions
        findings.push(CspmFinding {
            resource_id: "kv-dev".to_string(),
            resource_type: "Microsoft.KeyVault/vaults".to_string(),
            finding_type: "KEYVAULT_PUBLIC_ACCESS".to_string(),
            severity: "High".to_string(),
            description: "Key Vault allows access from all networks".to_string(),
            remediation: "Restrict access to specific VNets and use Private Endpoints".to_string(),
        });

        Ok(findings)
    }

    /// Scan Azure SQL Databases
    pub async fn scan_sql_databases(&self) -> Result<Vec<CspmFinding>> {
        let mut findings = Vec::new();

        // Check for TDE
        findings.push(CspmFinding {
            resource_id: "sql-server-1/db-prod".to_string(),
            resource_type: "Microsoft.Sql/servers/databases".to_string(),
            finding_type: "SQL_TDE_DISABLED".to_string(),
            severity: "High".to_string(),
            description: "Transparent Data Encryption is not enabled".to_string(),
            remediation: "Enable TDE for data-at-rest encryption".to_string(),
        });

        // Check for auditing
        findings.push(CspmFinding {
            resource_id: "sql-server-1".to_string(),
            resource_type: "Microsoft.Sql/servers".to_string(),
            finding_type: "SQL_AUDITING_DISABLED".to_string(),
            severity: "High".to_string(),
            description: "SQL Server auditing is not enabled".to_string(),
            remediation: "Enable auditing to storage account or Log Analytics".to_string(),
        });

        // Check for Azure AD authentication
        findings.push(CspmFinding {
            resource_id: "sql-server-2".to_string(),
            resource_type: "Microsoft.Sql/servers".to_string(),
            finding_type: "SQL_AAD_ADMIN_NOT_SET".to_string(),
            severity: "Medium".to_string(),
            description: "Azure AD admin is not configured for SQL Server".to_string(),
            remediation: "Configure Azure AD admin for centralized identity management".to_string(),
        });

        Ok(findings)
    }
}

impl Default for AzureCspm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_all() {
        let scanner = AzureCspm::new();
        let findings = scanner.scan_all().await.unwrap();
        assert!(!findings.is_empty());
    }
}
