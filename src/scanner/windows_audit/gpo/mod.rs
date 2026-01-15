//! GPO (Group Policy Object) collection module for Windows audit scanning
//!
//! Collects applied Group Policy settings from remote Windows systems for STIG compliance checking.

use anyhow::Result;
use super::WinRmClient;

/// GPO result from gpresult
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpoResult {
    pub computer_name: String,
    pub domain: Option<String>,
    pub site: Option<String>,
    pub last_refresh_time: Option<String>,
    pub computer_policies: Vec<AppliedPolicy>,
    pub user_policies: Vec<AppliedPolicy>,
    pub security_settings: SecuritySettings,
}

/// Applied GPO policy
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppliedPolicy {
    pub name: String,
    pub link_location: String,
    pub revision: Option<String>,
    pub filtering_status: String,
    pub settings: Vec<PolicySetting>,
}

/// Policy setting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicySetting {
    pub category: String,
    pub setting: String,
    pub value: String,
    pub state: PolicyState,
}

/// Policy setting state
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PolicyState {
    Enabled,
    Disabled,
    NotConfigured,
}

/// Security settings from GPO
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecuritySettings {
    pub password_policy: PasswordPolicySettings,
    pub account_lockout: AccountLockoutSettings,
    pub audit_policy: AuditPolicySettings,
    pub user_rights: Vec<UserRightAssignment>,
    pub security_options: Vec<SecurityOption>,
    pub event_log_settings: EventLogSettings,
}

/// Password policy settings
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PasswordPolicySettings {
    pub min_password_length: Option<u32>,
    pub password_history_count: Option<u32>,
    pub max_password_age_days: Option<u32>,
    pub min_password_age_days: Option<u32>,
    pub complexity_enabled: Option<bool>,
    pub reversible_encryption: Option<bool>,
}

/// Account lockout settings
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountLockoutSettings {
    pub lockout_threshold: Option<u32>,
    pub lockout_duration_minutes: Option<u32>,
    pub reset_lockout_counter_minutes: Option<u32>,
}

/// Audit policy settings
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AuditPolicySettings {
    pub account_logon: AuditSetting,
    pub account_management: AuditSetting,
    pub detailed_tracking: AuditSetting,
    pub ds_access: AuditSetting,
    pub logon_events: AuditSetting,
    pub object_access: AuditSetting,
    pub policy_change: AuditSetting,
    pub privilege_use: AuditSetting,
    pub system_events: AuditSetting,
}

/// Audit setting (Success/Failure)
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AuditSetting {
    pub success: bool,
    pub failure: bool,
}

/// User right assignment
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserRightAssignment {
    pub right: String,
    pub display_name: String,
    pub assigned_to: Vec<String>,
}

/// Security option
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityOption {
    pub name: String,
    pub display_name: String,
    pub value: String,
    pub numeric_value: Option<i64>,
}

/// Event log settings
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EventLogSettings {
    pub application_log_max_size_kb: Option<u32>,
    pub security_log_max_size_kb: Option<u32>,
    pub system_log_max_size_kb: Option<u32>,
    pub application_log_retention: Option<String>,
    pub security_log_retention: Option<String>,
    pub system_log_retention: Option<String>,
}

/// Collect GPO results via gpresult
pub async fn collect_gpo_result(client: &WinRmClient) -> Result<GpoResult> {
    // Get basic computer info
    let info_script = r#"
@{
    ComputerName = $env:COMPUTERNAME
    Domain = (Get-WmiObject Win32_ComputerSystem).Domain
    Site = (nltest /dsgetsite 2>$null | Select-Object -First 1)
} | ConvertTo-Json -Compress
"#;

    let info_output = client.execute_powershell(info_script).await?;
    let info: serde_json::Value = serde_json::from_str(info_output.trim()).unwrap_or_default();

    // Get applied GPOs
    let gpo_script = r#"
$gpos = @{
    Computer = @()
    User = @()
}

# Get Computer GPOs
$rsop = Get-WmiObject -Namespace "root\RSOP\Computer" -Class RSOP_GPO -ErrorAction SilentlyContinue
if ($rsop) {
    foreach ($gpo in $rsop) {
        $gpos.Computer += @{
            Name = $gpo.Name
            GuidName = $gpo.GuidName
            ID = $gpo.ID
            AccessDenied = $gpo.AccessDenied
            Enabled = $gpo.Enabled
            FileSystemPath = $gpo.FileSystemPath
            FilterAllowed = $gpo.FilterAllowed
            Version = $gpo.Version
        }
    }
}

# Get User GPOs
$rsop = Get-WmiObject -Namespace "root\RSOP\User" -Class RSOP_GPO -ErrorAction SilentlyContinue
if ($rsop) {
    foreach ($gpo in $rsop) {
        $gpos.User += @{
            Name = $gpo.Name
            GuidName = $gpo.GuidName
            ID = $gpo.ID
            AccessDenied = $gpo.AccessDenied
            Enabled = $gpo.Enabled
            FileSystemPath = $gpo.FileSystemPath
            FilterAllowed = $gpo.FilterAllowed
            Version = $gpo.Version
        }
    }
}

$gpos | ConvertTo-Json -Depth 3 -Compress
"#;

    let gpo_output = client.execute_powershell(gpo_script).await?;
    let gpos: serde_json::Value = serde_json::from_str(gpo_output.trim()).unwrap_or_default();

    // Collect security settings
    let security_settings = collect_security_settings(client).await?;

    // Parse computer policies
    let computer_policies = gpos.get("Computer")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(AppliedPolicy {
                        name: v.get("Name")?.as_str()?.to_string(),
                        link_location: v.get("FileSystemPath").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        revision: v.get("Version").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        filtering_status: if v.get("FilterAllowed").and_then(|x| x.as_bool()).unwrap_or(true) {
                            "Applied".to_string()
                        } else {
                            "Filtered".to_string()
                        },
                        settings: Vec::new(), // Settings are collected separately
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse user policies
    let user_policies = gpos.get("User")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(AppliedPolicy {
                        name: v.get("Name")?.as_str()?.to_string(),
                        link_location: v.get("FileSystemPath").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        revision: v.get("Version").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        filtering_status: if v.get("FilterAllowed").and_then(|x| x.as_bool()).unwrap_or(true) {
                            "Applied".to_string()
                        } else {
                            "Filtered".to_string()
                        },
                        settings: Vec::new(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(GpoResult {
        computer_name: info.get("ComputerName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        domain: info.get("Domain").and_then(|v| v.as_str()).map(|s| s.to_string()),
        site: info.get("Site").and_then(|v| v.as_str()).map(|s| s.to_string()),
        last_refresh_time: None,
        computer_policies,
        user_policies,
        security_settings,
    })
}

/// Collect security settings from local security policy
pub async fn collect_security_settings(client: &WinRmClient) -> Result<SecuritySettings> {
    let script = r#"
$settings = @{
    PasswordPolicy = @{}
    AccountLockout = @{}
    AuditPolicy = @{}
    UserRights = @()
    SecurityOptions = @()
    EventLog = @{}
}

# Export security policy to temp file
$tempFile = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tempFile /areas SECURITYPOLICY 2>$null | Out-Null

if (Test-Path $tempFile) {
    $content = Get-Content $tempFile -Raw

    # Parse Password Policy
    if ($content -match 'MinimumPasswordLength\s*=\s*(\d+)') { $settings.PasswordPolicy.MinLength = [int]$Matches[1] }
    if ($content -match 'PasswordHistorySize\s*=\s*(\d+)') { $settings.PasswordPolicy.HistoryCount = [int]$Matches[1] }
    if ($content -match 'MaximumPasswordAge\s*=\s*(\d+)') { $settings.PasswordPolicy.MaxAge = [int]$Matches[1] }
    if ($content -match 'MinimumPasswordAge\s*=\s*(\d+)') { $settings.PasswordPolicy.MinAge = [int]$Matches[1] }
    if ($content -match 'PasswordComplexity\s*=\s*(\d+)') { $settings.PasswordPolicy.Complexity = [int]$Matches[1] }
    if ($content -match 'ClearTextPassword\s*=\s*(\d+)') { $settings.PasswordPolicy.ReversibleEncryption = [int]$Matches[1] }

    # Parse Account Lockout
    if ($content -match 'LockoutBadCount\s*=\s*(\d+)') { $settings.AccountLockout.Threshold = [int]$Matches[1] }
    if ($content -match 'LockoutDuration\s*=\s*(\d+)') { $settings.AccountLockout.Duration = [int]$Matches[1] }
    if ($content -match 'ResetLockoutCount\s*=\s*(\d+)') { $settings.AccountLockout.ResetCounter = [int]$Matches[1] }

    Remove-Item $tempFile -Force
}

# Get Audit Policy via auditpol
$auditOutput = auditpol /get /category:* 2>$null
if ($auditOutput) {
    $settings.AuditPolicy = @{
        Raw = $auditOutput -join "`n"
    }
}

# Get User Rights
$tempFile2 = [System.IO.Path]::GetTempFileName()
secedit /export /cfg $tempFile2 /areas USER_RIGHTS 2>$null | Out-Null

if (Test-Path $tempFile2) {
    $content = Get-Content $tempFile2 -Raw
    $rights = @()

    # Common STIG-related user rights
    $rightMappings = @{
        'SeNetworkLogonRight' = 'Access this computer from the network'
        'SeDenyNetworkLogonRight' = 'Deny access to this computer from the network'
        'SeInteractiveLogonRight' = 'Allow log on locally'
        'SeDenyInteractiveLogonRight' = 'Deny log on locally'
        'SeRemoteInteractiveLogonRight' = 'Allow log on through Remote Desktop Services'
        'SeDenyRemoteInteractiveLogonRight' = 'Deny log on through Remote Desktop Services'
        'SeBackupPrivilege' = 'Back up files and directories'
        'SeRestorePrivilege' = 'Restore files and directories'
        'SeShutdownPrivilege' = 'Shut down the system'
        'SeTakeOwnershipPrivilege' = 'Take ownership of files or other objects'
        'SeDebugPrivilege' = 'Debug programs'
        'SeRemoteShutdownPrivilege' = 'Force shutdown from a remote system'
        'SeAuditPrivilege' = 'Generate security audits'
        'SeImpersonatePrivilege' = 'Impersonate a client after authentication'
        'SeLoadDriverPrivilege' = 'Load and unload device drivers'
        'SeSecurityPrivilege' = 'Manage auditing and security log'
        'SeSystemtimePrivilege' = 'Change the system time'
        'SeBatchLogonRight' = 'Log on as a batch job'
        'SeServiceLogonRight' = 'Log on as a service'
    }

    foreach ($right in $rightMappings.Keys) {
        if ($content -match "$right\s*=\s*(.+)") {
            $assigned = $Matches[1].Trim().Split(',') | ForEach-Object { $_.Trim() }
            $rights += @{
                Right = $right
                DisplayName = $rightMappings[$right]
                AssignedTo = $assigned
            }
        }
    }

    $settings.UserRights = $rights
    Remove-Item $tempFile2 -Force
}

# Get Event Log Settings
$settings.EventLog = @{
    Application = @{
        MaxSize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
        Retention = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name Retention -ErrorAction SilentlyContinue).Retention
    }
    Security = @{
        MaxSize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
        Retention = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name Retention -ErrorAction SilentlyContinue).Retention
    }
    System = @{
        MaxSize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
        Retention = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name Retention -ErrorAction SilentlyContinue).Retention
    }
}

$settings | ConvertTo-Json -Depth 4 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(SecuritySettings::default());
    }

    parse_security_settings(trimmed)
}

fn parse_security_settings(json_output: &str) -> Result<SecuritySettings> {
    let v: serde_json::Value = serde_json::from_str(json_output)?;

    let password_policy = v.get("PasswordPolicy").map(|pp| {
        PasswordPolicySettings {
            min_password_length: pp.get("MinLength").and_then(|x| x.as_u64()).map(|x| x as u32),
            password_history_count: pp.get("HistoryCount").and_then(|x| x.as_u64()).map(|x| x as u32),
            max_password_age_days: pp.get("MaxAge").and_then(|x| x.as_u64()).map(|x| x as u32),
            min_password_age_days: pp.get("MinAge").and_then(|x| x.as_u64()).map(|x| x as u32),
            complexity_enabled: pp.get("Complexity").and_then(|x| x.as_u64()).map(|x| x == 1),
            reversible_encryption: pp.get("ReversibleEncryption").and_then(|x| x.as_u64()).map(|x| x == 1),
        }
    }).unwrap_or_default();

    let account_lockout = v.get("AccountLockout").map(|al| {
        AccountLockoutSettings {
            lockout_threshold: al.get("Threshold").and_then(|x| x.as_u64()).map(|x| x as u32),
            lockout_duration_minutes: al.get("Duration").and_then(|x| x.as_u64()).map(|x| x as u32),
            reset_lockout_counter_minutes: al.get("ResetCounter").and_then(|x| x.as_u64()).map(|x| x as u32),
        }
    }).unwrap_or_default();

    let user_rights = v.get("UserRights")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|ur| {
                    Some(UserRightAssignment {
                        right: ur.get("Right")?.as_str()?.to_string(),
                        display_name: ur.get("DisplayName")?.as_str()?.to_string(),
                        assigned_to: ur.get("AssignedTo")
                            .and_then(|x| x.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let event_log_settings = v.get("EventLog").map(|el| {
        EventLogSettings {
            application_log_max_size_kb: el.get("Application")
                .and_then(|a| a.get("MaxSize"))
                .and_then(|x| x.as_u64())
                .map(|x| (x / 1024) as u32),
            security_log_max_size_kb: el.get("Security")
                .and_then(|a| a.get("MaxSize"))
                .and_then(|x| x.as_u64())
                .map(|x| (x / 1024) as u32),
            system_log_max_size_kb: el.get("System")
                .and_then(|a| a.get("MaxSize"))
                .and_then(|x| x.as_u64())
                .map(|x| (x / 1024) as u32),
            application_log_retention: el.get("Application")
                .and_then(|a| a.get("Retention"))
                .and_then(|x| x.as_i64())
                .map(|r| retention_to_string(r)),
            security_log_retention: el.get("Security")
                .and_then(|a| a.get("Retention"))
                .and_then(|x| x.as_i64())
                .map(|r| retention_to_string(r)),
            system_log_retention: el.get("System")
                .and_then(|a| a.get("Retention"))
                .and_then(|x| x.as_i64())
                .map(|r| retention_to_string(r)),
        }
    }).unwrap_or_default();

    Ok(SecuritySettings {
        password_policy,
        account_lockout,
        audit_policy: AuditPolicySettings::default(),
        user_rights,
        security_options: Vec::new(),
        event_log_settings,
    })
}

fn retention_to_string(retention: i64) -> String {
    match retention {
        0 => "Overwrite events as needed".to_string(),
        -1 => "Do not overwrite events".to_string(),
        n if n > 0 => format!("Overwrite events older than {} days", n),
        _ => "Unknown".to_string(),
    }
}

/// Get effective policy for a specific setting
pub async fn get_effective_policy(client: &WinRmClient, setting_path: &str) -> Result<Option<PolicySetting>> {
    let script = format!(r#"
$path = '{}'
$result = $null

# Try registry policy first
$regPath = "HKLM:\SOFTWARE\Policies\$path"
if (Test-Path $regPath) {{
    $value = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
    if ($value) {{
        $result = @{{
            Category = 'Registry Policy'
            Setting = $path
            Value = ($value | ConvertTo-Json -Compress)
            State = 'Enabled'
        }}
    }}
}}

if ($result) {{
    $result | ConvertTo-Json -Compress
}} else {{
    'null'
}}
"#, setting_path.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "null" || trimmed.is_empty() {
        return Ok(None);
    }

    let v: serde_json::Value = serde_json::from_str(trimmed)?;

    Ok(Some(PolicySetting {
        category: v.get("Category").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        setting: v.get("Setting").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        value: v.get("Value").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        state: match v.get("State").and_then(|x| x.as_str()).unwrap_or("") {
            "Enabled" => PolicyState::Enabled,
            "Disabled" => PolicyState::Disabled,
            _ => PolicyState::NotConfigured,
        },
    }))
}

/// Get detailed audit policy using auditpol
pub async fn get_detailed_audit_policy(client: &WinRmClient) -> Result<Vec<AuditSubcategory>> {
    let script = r#"
$results = @()
$output = auditpol /get /category:* /r 2>$null
if ($output) {
    $csv = $output | ConvertFrom-Csv
    foreach ($row in $csv) {
        $results += @{
            Category = $row.'Category/Subcategory'
            Guid = $row.'Subcategory GUID'
            InclusionSetting = $row.'Inclusion Setting'
            ExclusionSetting = if ($row.'Exclusion Setting') { $row.'Exclusion Setting' } else { '' }
        }
    }
}
$results | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
        let subcategories = arr.iter()
            .filter_map(|v| {
                let inclusion = v.get("InclusionSetting")?.as_str()?;
                Some(AuditSubcategory {
                    category: v.get("Category")?.as_str()?.to_string(),
                    guid: v.get("Guid").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    success: inclusion.contains("Success"),
                    failure: inclusion.contains("Failure"),
                })
            })
            .collect();
        Ok(subcategories)
    } else {
        Ok(Vec::new())
    }
}

/// Audit subcategory detail
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditSubcategory {
    pub category: String,
    pub guid: Option<String>,
    pub success: bool,
    pub failure: bool,
}

/// STIG-related GPO checks
pub mod stig_checks {
    use super::*;

    /// V-220709: Check minimum password length meets STIG requirement (14 characters)
    pub async fn check_min_password_length(client: &WinRmClient, required: u32) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.password_policy.min_password_length;
        let compliant = current.map(|v| v >= required).unwrap_or(false);
        Ok((compliant, current))
    }

    /// V-220710: Check password history meets STIG requirement (24 passwords)
    pub async fn check_password_history(client: &WinRmClient, required: u32) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.password_policy.password_history_count;
        let compliant = current.map(|v| v >= required).unwrap_or(false);
        Ok((compliant, current))
    }

    /// V-220711: Check maximum password age meets STIG requirement (60 days max)
    pub async fn check_max_password_age(client: &WinRmClient, max_days: u32) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.password_policy.max_password_age_days;
        let compliant = current.map(|v| v <= max_days && v > 0).unwrap_or(false);
        Ok((compliant, current))
    }

    /// V-220712: Check password complexity is enabled
    pub async fn check_password_complexity(client: &WinRmClient) -> Result<(bool, Option<bool>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.password_policy.complexity_enabled;
        let compliant = current.unwrap_or(false);
        Ok((compliant, current))
    }

    /// V-220713: Check account lockout threshold (3 attempts max)
    pub async fn check_lockout_threshold(client: &WinRmClient, max_attempts: u32) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.account_lockout.lockout_threshold;
        let compliant = current.map(|v| v > 0 && v <= max_attempts).unwrap_or(false);
        Ok((compliant, current))
    }

    /// V-220714: Check lockout duration (15 minutes minimum or until admin unlock)
    pub async fn check_lockout_duration(client: &WinRmClient, min_minutes: u32) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;
        let current = settings.account_lockout.lockout_duration_minutes;
        // 0 means until admin unlocks, which is compliant
        let compliant = current.map(|v| v == 0 || v >= min_minutes).unwrap_or(false);
        Ok((compliant, current))
    }

    /// Check user right assignment
    pub async fn check_user_right(
        client: &WinRmClient,
        right: &str,
        allowed_principals: &[&str]
    ) -> Result<(bool, Vec<String>)> {
        let settings = collect_security_settings(client).await?;

        let assignment = settings.user_rights.iter()
            .find(|ur| ur.right == right);

        match assignment {
            Some(ur) => {
                let extra_principals: Vec<String> = ur.assigned_to.iter()
                    .filter(|p| !allowed_principals.iter().any(|ap| p.contains(ap)))
                    .cloned()
                    .collect();
                let compliant = extra_principals.is_empty();
                Ok((compliant, ur.assigned_to.clone()))
            }
            None => Ok((true, Vec::new())), // If not assigned to anyone, that may be compliant
        }
    }

    /// Check event log minimum size (STIG typically requires 196608 KB for Security)
    pub async fn check_event_log_size(
        client: &WinRmClient,
        log_name: &str,
        min_size_kb: u32,
    ) -> Result<(bool, Option<u32>)> {
        let settings = collect_security_settings(client).await?;

        let current = match log_name.to_lowercase().as_str() {
            "security" => settings.event_log_settings.security_log_max_size_kb,
            "application" => settings.event_log_settings.application_log_max_size_kb,
            "system" => settings.event_log_settings.system_log_max_size_kb,
            _ => None,
        };

        let compliant = current.map(|v| v >= min_size_kb).unwrap_or(false);
        Ok((compliant, current))
    }
}
