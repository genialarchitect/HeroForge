//! Windows Audit Module
//!
//! Credentialed Windows scanning using WinRM/PowerShell.
//! Supports STIG compliance checking for CAT I/II/III controls.
//! Includes OVAL collector integration for SCAP-based assessments.

pub mod types;
pub mod client;
pub mod registry;
pub mod gpo;
pub mod patches;
pub mod services;
pub mod users;
pub mod firewall;
pub mod filesystem;
pub mod stig;
pub mod oval_integration;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

pub use types::*;
pub use client::WinRmClient;

/// Main Windows audit scanner
pub struct WindowsAuditScanner {
    client: Arc<RwLock<WinRmClient>>,
    config: WindowsAuditConfig,
}

impl WindowsAuditScanner {
    /// Create a new Windows audit scanner
    pub fn new(config: WindowsAuditConfig) -> Self {
        let client = WinRmClient::new(&config.target, config.credentials.clone());
        Self {
            client: Arc::new(RwLock::new(client)),
            config,
        }
    }

    /// Run a full Windows audit scan
    pub async fn run_full_scan(&self) -> Result<WindowsAuditResult> {
        let mut result = WindowsAuditResult::new(&self.config.target);

        // Collect system information
        let system_info = self.collect_system_info().await?;
        result.system_info = Some(system_info);

        // Collect security policies
        let policies = self.collect_security_policies().await?;
        result.security_policies = policies;

        // Collect installed patches
        let patches = self.collect_installed_patches().await?;
        result.installed_patches = patches;

        // Collect services
        let services = self.collect_services().await?;
        result.services = services;

        // Collect local users and groups
        let (users, groups) = self.collect_users_and_groups().await?;
        result.local_users = users;
        result.local_groups = groups;

        // Collect firewall rules
        let firewall_rules = self.collect_firewall_rules().await?;
        result.firewall_rules = firewall_rules;

        // Run STIG checks if enabled
        if self.config.run_stig_checks {
            let stig_results = self.run_stig_checks(&result).await?;
            result.stig_results = stig_results;
        }

        result.completed_at = Some(chrono::Utc::now());
        Ok(result)
    }

    /// Collect system information
    async fn collect_system_info(&self) -> Result<WindowsSystemInfo> {
        let client = self.client.read().await;

        // Get OS info via WMI
        let os_info = client.execute_powershell(
            "Get-CimInstance -ClassName Win32_OperatingSystem | ConvertTo-Json"
        ).await?;

        // Get computer info
        let computer_info = client.execute_powershell(
            "Get-CimInstance -ClassName Win32_ComputerSystem | ConvertTo-Json"
        ).await?;

        WindowsSystemInfo::from_wmi(&os_info, &computer_info)
    }

    /// Collect security policies
    async fn collect_security_policies(&self) -> Result<SecurityPolicies> {
        let client = self.client.read().await;

        // Export and read security policy
        let policy_script = r#"
            secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
            Get-Content "$env:TEMP\secpol.cfg"
            Remove-Item "$env:TEMP\secpol.cfg" -Force
        "#;

        let policy_output = client.execute_powershell(policy_script).await?;
        SecurityPolicies::parse(&policy_output)
    }

    /// Collect installed patches
    async fn collect_installed_patches(&self) -> Result<Vec<InstalledPatch>> {
        let client = self.client.read().await;

        let patches_output = client.execute_powershell(
            "Get-HotFix | Select-Object HotFixID, Description, InstalledOn | ConvertTo-Json"
        ).await?;

        patches::parse_hotfix_list(&patches_output)
    }

    /// Collect Windows services
    async fn collect_services(&self) -> Result<Vec<WindowsService>> {
        let client = self.client.read().await;

        let services_output = client.execute_powershell(
            "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
        ).await?;

        services::parse_service_list(&services_output)
    }

    /// Collect local users and groups
    async fn collect_users_and_groups(&self) -> Result<(Vec<LocalUser>, Vec<LocalGroup>)> {
        let client = self.client.read().await;

        let users_output = client.execute_powershell(
            "Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired | ConvertTo-Json"
        ).await?;

        let groups_output = client.execute_powershell(
            "Get-LocalGroup | Select-Object Name, Description | ConvertTo-Json"
        ).await?;

        let users = users::parse_user_list(&users_output)?;
        let groups = users::parse_group_list(&groups_output)?;
        Ok((users, groups))
    }

    /// Collect firewall rules
    async fn collect_firewall_rules(&self) -> Result<Vec<FirewallRule>> {
        let client = self.client.read().await;

        let rules_output = client.execute_powershell(
            "Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | \
             Select-Object Name, DisplayName, Direction, Action, Profile | \
             ConvertTo-Json -Depth 2"
        ).await?;

        firewall::parse_firewall_rules(&rules_output)
    }

    /// Run STIG compliance checks
    async fn run_stig_checks(&self, scan_data: &WindowsAuditResult) -> Result<Vec<StigCheckResult>> {
        let mut results = Vec::new();

        // Run CAT I checks (highest priority)
        let cat1_results = stig::checks::run_cat1_checks(scan_data).await?;
        results.extend(cat1_results);

        // Run CAT II checks
        let cat2_results = stig::checks::run_cat2_checks(scan_data).await?;
        results.extend(cat2_results);

        // Run CAT III checks
        if self.config.include_cat3 {
            let cat3_results = stig::checks::run_cat3_checks(scan_data).await?;
            results.extend(cat3_results);
        }

        Ok(results)
    }
}
