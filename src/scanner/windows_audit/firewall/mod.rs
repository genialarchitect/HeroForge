//! Windows Firewall collection module for Windows audit scanning
//!
//! Collects firewall profiles, rules, and configuration for STIG compliance.

use anyhow::Result;
use super::types::{FirewallRule, FirewallDirection, FirewallAction, FirewallProfile};
use super::WinRmClient;

/// Firewall profile status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallProfileStatus {
    pub profile: FirewallProfile,
    pub enabled: bool,
    pub default_inbound_action: FirewallAction,
    pub default_outbound_action: FirewallAction,
    pub allow_inbound_rules: bool,
    pub allow_local_firewall_rules: bool,
    pub allow_local_ipsec_rules: bool,
    pub notify_on_listen: bool,
    pub log_allowed_connections: bool,
    pub log_dropped_connections: bool,
    pub log_file_path: Option<String>,
    pub log_max_size_kb: Option<u32>,
}

/// Firewall overall status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallStatus {
    pub domain_profile: FirewallProfileStatus,
    pub private_profile: FirewallProfileStatus,
    pub public_profile: FirewallProfileStatus,
    pub total_rules: usize,
    pub enabled_rules: usize,
}

/// Extended firewall rule with security details
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FirewallRuleDetail {
    pub rule: FirewallRule,
    pub description: Option<String>,
    pub group: Option<String>,
    pub interface_types: Vec<String>,
    pub local_addresses: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub icmp_type: Option<String>,
    pub edge_traversal: bool,
    pub owner: Option<String>,
}

/// Parse firewall rules from PowerShell JSON output
pub fn parse_firewall_rules(json_output: &str) -> Result<Vec<FirewallRule>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let rules = arr.iter()
            .filter_map(|v| {
                Some(FirewallRule {
                    name: v.get("Name")?.as_str()?.to_string(),
                    display_name: v.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    enabled: v.get("Enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                    direction: parse_direction(v.get("Direction").and_then(|x| x.as_str()).unwrap_or("")),
                    action: parse_action(v.get("Action").and_then(|x| x.as_str()).unwrap_or("")),
                    profile: parse_profile(v.get("Profile").and_then(|x| x.as_str()).unwrap_or("Any")),
                    local_port: v.get("LocalPort").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    remote_port: v.get("RemotePort").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    protocol: v.get("Protocol").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    program: v.get("Program").and_then(|x| x.as_str()).map(|s| s.to_string()),
                })
            })
            .collect();
        Ok(rules)
    } else {
        Ok(Vec::new())
    }
}

fn parse_direction(s: &str) -> FirewallDirection {
    match s.to_lowercase().as_str() {
        "inbound" | "1" => FirewallDirection::Inbound,
        "outbound" | "2" => FirewallDirection::Outbound,
        _ => FirewallDirection::Inbound,
    }
}

fn parse_action(s: &str) -> FirewallAction {
    match s.to_lowercase().as_str() {
        "allow" | "2" => FirewallAction::Allow,
        "block" | "4" => FirewallAction::Block,
        _ => FirewallAction::Block,
    }
}

fn parse_profile(s: &str) -> FirewallProfile {
    match s.to_lowercase().as_str() {
        "domain" | "1" => FirewallProfile::Domain,
        "private" | "2" => FirewallProfile::Private,
        "public" | "4" => FirewallProfile::Public,
        _ => FirewallProfile::Any,
    }
}

/// Get firewall overall status
pub async fn get_firewall_status(client: &WinRmClient) -> Result<FirewallStatus> {
    let script = r#"
$profiles = @('Domain', 'Private', 'Public')
$result = @{
    Profiles = @()
    TotalRules = (Get-NetFirewallRule).Count
    EnabledRules = (Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }).Count
}

foreach ($profileName in $profiles) {
    $profile = Get-NetFirewallProfile -Name $profileName
    $result.Profiles += @{
        Name = $profileName
        Enabled = $profile.Enabled
        DefaultInboundAction = $profile.DefaultInboundAction.ToString()
        DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
        AllowInboundRules = $profile.AllowInboundRules
        AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
        AllowLocalIPsecRules = $profile.AllowLocalIPsecRules
        NotifyOnListen = $profile.NotifyOnListen
        LogAllowed = $profile.LogAllowed
        LogBlocked = $profile.LogBlocked
        LogFileName = $profile.LogFileName
        LogMaxSizeKilobytes = $profile.LogMaxSizeKilobytes
    }
}

$result | ConvertTo-Json -Depth 3 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(FirewallStatus {
            domain_profile: default_profile_status(FirewallProfile::Domain),
            private_profile: default_profile_status(FirewallProfile::Private),
            public_profile: default_profile_status(FirewallProfile::Public),
            total_rules: 0,
            enabled_rules: 0,
        });
    }

    parse_firewall_status(trimmed)
}

fn default_profile_status(profile: FirewallProfile) -> FirewallProfileStatus {
    FirewallProfileStatus {
        profile,
        enabled: false,
        default_inbound_action: FirewallAction::Block,
        default_outbound_action: FirewallAction::Allow,
        allow_inbound_rules: true,
        allow_local_firewall_rules: true,
        allow_local_ipsec_rules: true,
        notify_on_listen: true,
        log_allowed_connections: false,
        log_dropped_connections: false,
        log_file_path: None,
        log_max_size_kb: None,
    }
}

fn parse_firewall_status(json_output: &str) -> Result<FirewallStatus> {
    let v: serde_json::Value = serde_json::from_str(json_output)?;

    let profiles = v.get("Profiles").and_then(|x| x.as_array());

    let parse_profile_status = |profile_name: &str| -> FirewallProfileStatus {
        let profile_val = profiles
            .and_then(|arr| arr.iter().find(|p| p.get("Name").and_then(|n| n.as_str()) == Some(profile_name)));

        match profile_val {
            Some(p) => FirewallProfileStatus {
                profile: match profile_name {
                    "Domain" => FirewallProfile::Domain,
                    "Private" => FirewallProfile::Private,
                    "Public" => FirewallProfile::Public,
                    _ => FirewallProfile::Any,
                },
                enabled: p.get("Enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                default_inbound_action: parse_action(p.get("DefaultInboundAction").and_then(|x| x.as_str()).unwrap_or("")),
                default_outbound_action: parse_action(p.get("DefaultOutboundAction").and_then(|x| x.as_str()).unwrap_or("")),
                allow_inbound_rules: p.get("AllowInboundRules").and_then(|x| x.as_bool()).unwrap_or(true),
                allow_local_firewall_rules: p.get("AllowLocalFirewallRules").and_then(|x| x.as_bool()).unwrap_or(true),
                allow_local_ipsec_rules: p.get("AllowLocalIPsecRules").and_then(|x| x.as_bool()).unwrap_or(true),
                notify_on_listen: p.get("NotifyOnListen").and_then(|x| x.as_bool()).unwrap_or(true),
                log_allowed_connections: p.get("LogAllowed").and_then(|x| x.as_bool()).unwrap_or(false),
                log_dropped_connections: p.get("LogBlocked").and_then(|x| x.as_bool()).unwrap_or(false),
                log_file_path: p.get("LogFileName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                log_max_size_kb: p.get("LogMaxSizeKilobytes").and_then(|x| x.as_u64()).map(|x| x as u32),
            },
            None => default_profile_status(match profile_name {
                "Domain" => FirewallProfile::Domain,
                "Private" => FirewallProfile::Private,
                "Public" => FirewallProfile::Public,
                _ => FirewallProfile::Any,
            }),
        }
    };

    Ok(FirewallStatus {
        domain_profile: parse_profile_status("Domain"),
        private_profile: parse_profile_status("Private"),
        public_profile: parse_profile_status("Public"),
        total_rules: v.get("TotalRules").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
        enabled_rules: v.get("EnabledRules").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
    })
}

/// Collect all firewall rules
pub async fn collect_firewall_rules(client: &WinRmClient) -> Result<Vec<FirewallRule>> {
    let script = r#"
Get-NetFirewallRule | ForEach-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter
    $appFilter = $_ | Get-NetFirewallApplicationFilter

    @{
        Name = $_.Name
        DisplayName = $_.DisplayName
        Enabled = ($_.Enabled -eq 'True')
        Direction = $_.Direction.ToString()
        Action = $_.Action.ToString()
        Profile = $_.Profile.ToString()
        LocalPort = $portFilter.LocalPort
        RemotePort = $portFilter.RemotePort
        Protocol = $portFilter.Protocol
        Program = $appFilter.Program
    }
} | ConvertTo-Json -Depth 2 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_firewall_rules(trimmed)
}

/// Collect firewall rules with extended details
pub async fn collect_firewall_rules_detailed(client: &WinRmClient) -> Result<Vec<FirewallRuleDetail>> {
    let script = r#"
Get-NetFirewallRule | ForEach-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter
    $appFilter = $_ | Get-NetFirewallApplicationFilter
    $addrFilter = $_ | Get-NetFirewallAddressFilter
    $ifFilter = $_ | Get-NetFirewallInterfaceTypeFilter

    @{
        Name = $_.Name
        DisplayName = $_.DisplayName
        Description = $_.Description
        Group = $_.Group
        Enabled = ($_.Enabled -eq 'True')
        Direction = $_.Direction.ToString()
        Action = $_.Action.ToString()
        Profile = $_.Profile.ToString()
        LocalPort = $portFilter.LocalPort
        RemotePort = $portFilter.RemotePort
        Protocol = $portFilter.Protocol
        Program = $appFilter.Program
        LocalAddress = $addrFilter.LocalAddress
        RemoteAddress = $addrFilter.RemoteAddress
        InterfaceType = $ifFilter.InterfaceType
        IcmpType = $portFilter.IcmpType
        EdgeTraversalPolicy = $_.EdgeTraversalPolicy.ToString()
        Owner = $_.Owner
    }
} | ConvertTo-Json -Depth 2 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_firewall_rules_detailed(trimmed)
}

fn parse_firewall_rules_detailed(json_output: &str) -> Result<Vec<FirewallRuleDetail>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let rules = arr.iter()
            .filter_map(|v| {
                let rule = FirewallRule {
                    name: v.get("Name")?.as_str()?.to_string(),
                    display_name: v.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    enabled: v.get("Enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                    direction: parse_direction(v.get("Direction").and_then(|x| x.as_str()).unwrap_or("")),
                    action: parse_action(v.get("Action").and_then(|x| x.as_str()).unwrap_or("")),
                    profile: parse_profile(v.get("Profile").and_then(|x| x.as_str()).unwrap_or("Any")),
                    local_port: v.get("LocalPort").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    remote_port: v.get("RemotePort").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    protocol: v.get("Protocol").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    program: v.get("Program").and_then(|x| x.as_str()).map(|s| s.to_string()),
                };

                Some(FirewallRuleDetail {
                    rule,
                    description: v.get("Description").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    group: v.get("Group").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    interface_types: v.get("InterfaceType")
                        .and_then(|x| x.as_str())
                        .map(|s| vec![s.to_string()])
                        .unwrap_or_default(),
                    local_addresses: parse_address_array(v.get("LocalAddress")),
                    remote_addresses: parse_address_array(v.get("RemoteAddress")),
                    icmp_type: v.get("IcmpType").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    edge_traversal: v.get("EdgeTraversalPolicy").and_then(|x| x.as_str()).map(|s| s != "Block").unwrap_or(false),
                    owner: v.get("Owner").and_then(|x| x.as_str()).map(|s| s.to_string()),
                })
            })
            .collect();
        Ok(rules)
    } else {
        Ok(Vec::new())
    }
}

fn parse_address_array(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(v) if v.is_array() => {
            v.as_array()
                .unwrap()
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        }
        Some(v) if v.is_string() => {
            vec![v.as_str().unwrap().to_string()]
        }
        _ => Vec::new(),
    }
}

/// Get rules that allow inbound connections from any address
pub async fn find_permissive_inbound_rules(client: &WinRmClient) -> Result<Vec<FirewallRule>> {
    let rules = collect_firewall_rules(client).await?;

    Ok(rules.into_iter()
        .filter(|r| {
            r.enabled &&
            matches!(r.direction, FirewallDirection::Inbound) &&
            matches!(r.action, FirewallAction::Allow)
        })
        .collect())
}

/// Get rules for a specific program
pub async fn get_rules_for_program(client: &WinRmClient, program_path: &str) -> Result<Vec<FirewallRule>> {
    let rules = collect_firewall_rules(client).await?;
    let program_lower = program_path.to_lowercase();

    Ok(rules.into_iter()
        .filter(|r| {
            r.program.as_ref()
                .map(|p| p.to_lowercase().contains(&program_lower))
                .unwrap_or(false)
        })
        .collect())
}

/// STIG-related firewall checks
pub mod stig_checks {
    use super::*;

    /// V-220743: Windows Firewall must be enabled for Domain profile
    pub async fn check_domain_firewall_enabled(client: &WinRmClient) -> Result<bool> {
        let status = get_firewall_status(client).await?;
        Ok(status.domain_profile.enabled)
    }

    /// V-220744: Windows Firewall must be enabled for Private profile
    pub async fn check_private_firewall_enabled(client: &WinRmClient) -> Result<bool> {
        let status = get_firewall_status(client).await?;
        Ok(status.private_profile.enabled)
    }

    /// V-220745: Windows Firewall must be enabled for Public profile
    pub async fn check_public_firewall_enabled(client: &WinRmClient) -> Result<bool> {
        let status = get_firewall_status(client).await?;
        Ok(status.public_profile.enabled)
    }

    /// V-220746: Firewall must block inbound connections by default
    pub async fn check_inbound_connections_blocked(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let status = get_firewall_status(client).await?;
        let mut issues = Vec::new();

        if !matches!(status.domain_profile.default_inbound_action, FirewallAction::Block) {
            issues.push("Domain profile allows inbound by default".to_string());
        }
        if !matches!(status.private_profile.default_inbound_action, FirewallAction::Block) {
            issues.push("Private profile allows inbound by default".to_string());
        }
        if !matches!(status.public_profile.default_inbound_action, FirewallAction::Block) {
            issues.push("Public profile allows inbound by default".to_string());
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220747: Firewall logging must be enabled
    pub async fn check_firewall_logging_enabled(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let status = get_firewall_status(client).await?;
        let mut issues = Vec::new();

        // Check Domain profile
        if !status.domain_profile.log_dropped_connections {
            issues.push("Domain profile: dropped connections not logged".to_string());
        }
        if !status.domain_profile.log_allowed_connections {
            issues.push("Domain profile: allowed connections not logged".to_string());
        }

        // Check Private profile
        if !status.private_profile.log_dropped_connections {
            issues.push("Private profile: dropped connections not logged".to_string());
        }

        // Check Public profile
        if !status.public_profile.log_dropped_connections {
            issues.push("Public profile: dropped connections not logged".to_string());
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220748: Local firewall rules must not override domain policy
    pub async fn check_local_rules_not_merged(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let status = get_firewall_status(client).await?;
        let mut issues = Vec::new();

        // In high-security environments, local rules should not be merged
        if status.domain_profile.allow_local_firewall_rules {
            issues.push("Domain profile allows local firewall rules".to_string());
        }

        Ok((issues.is_empty(), issues))
    }

    /// Check for potentially dangerous inbound rules
    pub async fn check_dangerous_inbound_rules(client: &WinRmClient) -> Result<Vec<(String, String)>> {
        let rules = collect_firewall_rules_detailed(client).await?;
        let mut dangerous = Vec::new();

        for rule in rules {
            if !rule.rule.enabled || !matches!(rule.rule.direction, FirewallDirection::Inbound) {
                continue;
            }

            // Check for rules allowing any address
            if rule.remote_addresses.iter().any(|a| a == "Any" || a == "*" || a == "0.0.0.0/0") {
                // Check for dangerous ports
                if let Some(port) = &rule.rule.local_port {
                    let dangerous_ports = ["21", "23", "445", "135", "139", "3389", "5985", "5986"];
                    for dp in dangerous_ports {
                        if port.contains(dp) {
                            dangerous.push((
                                rule.rule.display_name.clone(),
                                format!("Allows inbound on port {} from any address", dp)
                            ));
                        }
                    }
                }
            }
        }

        Ok(dangerous)
    }

    /// Check all firewall profiles are properly configured
    pub async fn check_all_profiles(client: &WinRmClient) -> Result<Vec<(String, bool, String)>> {
        let mut results = Vec::new();

        let domain_enabled = check_domain_firewall_enabled(client).await?;
        results.push(("Domain profile enabled".to_string(), domain_enabled,
            if domain_enabled { "Compliant".to_string() } else { "Domain profile is disabled".to_string() }));

        let private_enabled = check_private_firewall_enabled(client).await?;
        results.push(("Private profile enabled".to_string(), private_enabled,
            if private_enabled { "Compliant".to_string() } else { "Private profile is disabled".to_string() }));

        let public_enabled = check_public_firewall_enabled(client).await?;
        results.push(("Public profile enabled".to_string(), public_enabled,
            if public_enabled { "Compliant".to_string() } else { "Public profile is disabled".to_string() }));

        let (inbound_blocked, inbound_issues) = check_inbound_connections_blocked(client).await?;
        results.push(("Inbound blocked by default".to_string(), inbound_blocked,
            if inbound_blocked { "Compliant".to_string() } else { inbound_issues.join(", ") }));

        Ok(results)
    }
}
