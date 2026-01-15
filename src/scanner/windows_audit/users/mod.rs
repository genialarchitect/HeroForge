//! Windows users and groups collection module for Windows audit scanning
//!
//! Collects local users, groups, privileges, and security settings for STIG compliance.

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use super::types::{LocalUser, LocalGroup};
use super::WinRmClient;

/// Extended user information with security details
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserSecurityInfo {
    pub user: LocalUser,
    pub sid: String,
    pub user_flags: Vec<String>,
    pub logon_count: u32,
    pub bad_password_count: u32,
    pub account_expires: Option<DateTime<Utc>>,
    pub password_age_days: Option<u32>,
    pub privileges: Vec<String>,
    pub is_admin: bool,
    pub is_guest: bool,
}

/// Group membership detail
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupMembership {
    pub group: LocalGroup,
    pub sid: String,
    pub group_type: GroupType,
    pub member_count: usize,
    pub nested_groups: Vec<String>,
}

/// Group type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GroupType {
    BuiltIn,
    Local,
    Domain,
    Unknown,
}

/// Parse user list from PowerShell JSON output
pub fn parse_user_list(json_output: &str) -> Result<Vec<LocalUser>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let users = arr.iter()
            .filter_map(|v| {
                Some(LocalUser {
                    name: v.get("Name")?.as_str()?.to_string(),
                    enabled: v.get("Enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                    password_required: v.get("PasswordRequired").and_then(|x| x.as_bool()).unwrap_or(true),
                    password_changeable: v.get("PasswordChangeableDate").is_some(),
                    password_expires: v.get("PasswordExpires").and_then(|x| x.as_bool()).unwrap_or(true),
                    last_logon: v.get("LastLogon").and_then(|x| x.as_str()).and_then(parse_datetime),
                    password_last_set: v.get("PasswordLastSet").and_then(|x| x.as_str()).and_then(parse_datetime),
                    groups: v.get("Groups")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|g| g.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                })
            })
            .collect();
        Ok(users)
    } else {
        Ok(Vec::new())
    }
}

fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    // Try ISO 8601 format first
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try other common formats
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%m/%d/%Y %H:%M:%S") {
        return Some(DateTime::from_naive_utc_and_offset(dt, Utc));
    }
    None
}

/// Parse group list from PowerShell JSON output
pub fn parse_group_list(json_output: &str) -> Result<Vec<LocalGroup>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let groups = arr.iter()
            .filter_map(|v| {
                Some(LocalGroup {
                    name: v.get("Name")?.as_str()?.to_string(),
                    description: v.get("Description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    members: v.get("Members")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|m| m.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                })
            })
            .collect();
        Ok(groups)
    } else {
        Ok(Vec::new())
    }
}

/// Collect all local users
pub async fn collect_local_users(client: &WinRmClient) -> Result<Vec<LocalUser>> {
    let script = r#"
$users = Get-LocalUser | ForEach-Object {
    $groups = @()
    try {
        $groups = (Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name -contains $_.Name
        }).Name
    } catch {}

    @{
        Name = $_.Name
        Enabled = $_.Enabled
        PasswordRequired = $_.PasswordRequired
        PasswordExpires = $_.PasswordExpires
        LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString("o") } else { $null }
        PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("o") } else { $null }
        Description = $_.Description
        SID = $_.SID.Value
        Groups = $groups
    }
}
$users | ConvertTo-Json -Depth 2 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    parse_user_list(trimmed)
}

/// Collect local users with extended security information
pub async fn collect_users_with_security(client: &WinRmClient) -> Result<Vec<UserSecurityInfo>> {
    let script = r#"
$results = @()
$users = Get-LocalUser

foreach ($user in $users) {
    $groups = @()
    $isAdmin = $false

    # Get group memberships
    try {
        $allGroups = Get-LocalGroup
        foreach ($group in $allGroups) {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            if ($members.Name -contains $user.Name -or $members.SID -contains $user.SID) {
                $groups += $group.Name
                if ($group.Name -eq 'Administrators') {
                    $isAdmin = $true
                }
            }
        }
    } catch {}

    # Calculate password age
    $passwordAgeDays = $null
    if ($user.PasswordLastSet) {
        $passwordAgeDays = ((Get-Date) - $user.PasswordLastSet).Days
    }

    $results += @{
        Name = $user.Name
        SID = $user.SID.Value
        Enabled = $user.Enabled
        PasswordRequired = $user.PasswordRequired
        PasswordExpires = $user.PasswordExpires
        LastLogon = if ($user.LastLogon) { $user.LastLogon.ToString("o") } else { $null }
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("o") } else { $null }
        AccountExpires = if ($user.AccountExpires) { $user.AccountExpires.ToString("o") } else { $null }
        PasswordAgeDays = $passwordAgeDays
        Description = $user.Description
        Groups = $groups
        IsAdmin = $isAdmin
        IsGuest = ($user.Name -eq 'Guest')
        UserMayChangePassword = $user.UserMayChangePassword
    }
}

$results | ConvertTo-Json -Depth 2 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_users_with_security(trimmed)
}

fn parse_users_with_security(json_output: &str) -> Result<Vec<UserSecurityInfo>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let users = arr.iter()
            .filter_map(|v| {
                let user = LocalUser {
                    name: v.get("Name")?.as_str()?.to_string(),
                    enabled: v.get("Enabled").and_then(|x| x.as_bool()).unwrap_or(false),
                    password_required: v.get("PasswordRequired").and_then(|x| x.as_bool()).unwrap_or(true),
                    password_changeable: v.get("UserMayChangePassword").and_then(|x| x.as_bool()).unwrap_or(true),
                    password_expires: v.get("PasswordExpires").and_then(|x| x.as_bool()).unwrap_or(true),
                    last_logon: v.get("LastLogon").and_then(|x| x.as_str()).and_then(parse_datetime),
                    password_last_set: v.get("PasswordLastSet").and_then(|x| x.as_str()).and_then(parse_datetime),
                    groups: v.get("Groups")
                        .and_then(|x| x.as_array())
                        .map(|a| a.iter().filter_map(|g| g.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                };

                Some(UserSecurityInfo {
                    sid: v.get("SID").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    user_flags: Vec::new(),
                    logon_count: 0,
                    bad_password_count: 0,
                    account_expires: v.get("AccountExpires").and_then(|x| x.as_str()).and_then(parse_datetime),
                    password_age_days: v.get("PasswordAgeDays").and_then(|x| x.as_u64()).map(|x| x as u32),
                    privileges: Vec::new(),
                    is_admin: v.get("IsAdmin").and_then(|x| x.as_bool()).unwrap_or(false),
                    is_guest: v.get("IsGuest").and_then(|x| x.as_bool()).unwrap_or(false),
                    user,
                })
            })
            .collect();
        Ok(users)
    } else {
        Ok(Vec::new())
    }
}

/// Collect all local groups with members
pub async fn collect_local_groups(client: &WinRmClient) -> Result<Vec<LocalGroup>> {
    let script = r#"
$groups = Get-LocalGroup | ForEach-Object {
    $members = @()
    try {
        $members = (Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue).Name
    } catch {}

    @{
        Name = $_.Name
        Description = $_.Description
        SID = $_.SID.Value
        Members = $members
    }
}
$groups | ConvertTo-Json -Depth 2 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    parse_group_list(trimmed)
}

/// Get members of the Administrators group
pub async fn get_administrators_group_members(client: &WinRmClient) -> Result<Vec<String>> {
    let script = r#"
$members = @()
try {
    $members = (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
} catch {}
$members | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    Ok(serde_json::from_str(trimmed).unwrap_or_default())
}

/// Get members of the Remote Desktop Users group
pub async fn get_rdp_users_group_members(client: &WinRmClient) -> Result<Vec<String>> {
    let script = r#"
$members = @()
try {
    $members = (Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue).Name
} catch {}
$members | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    Ok(serde_json::from_str(trimmed).unwrap_or_default())
}

/// Check if a specific user exists and get details
pub async fn get_user_details(client: &WinRmClient, username: &str) -> Result<Option<UserSecurityInfo>> {
    let script = format!(r#"
$user = Get-LocalUser -Name '{}' -ErrorAction SilentlyContinue
if (-not $user) {{ Write-Output 'null'; exit }}

$groups = @()
$isAdmin = $false

try {{
    $allGroups = Get-LocalGroup
    foreach ($group in $allGroups) {{
        $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
        if ($members.Name -contains $user.Name -or $members.SID -contains $user.SID) {{
            $groups += $group.Name
            if ($group.Name -eq 'Administrators') {{
                $isAdmin = $true
            }}
        }}
    }}
}} catch {{}}

$passwordAgeDays = $null
if ($user.PasswordLastSet) {{
    $passwordAgeDays = ((Get-Date) - $user.PasswordLastSet).Days
}}

@{{
    Name = $user.Name
    SID = $user.SID.Value
    Enabled = $user.Enabled
    PasswordRequired = $user.PasswordRequired
    PasswordExpires = $user.PasswordExpires
    LastLogon = if ($user.LastLogon) {{ $user.LastLogon.ToString("o") }} else {{ $null }}
    PasswordLastSet = if ($user.PasswordLastSet) {{ $user.PasswordLastSet.ToString("o") }} else {{ $null }}
    AccountExpires = if ($user.AccountExpires) {{ $user.AccountExpires.ToString("o") }} else {{ $null }}
    PasswordAgeDays = $passwordAgeDays
    Description = $user.Description
    Groups = $groups
    IsAdmin = $isAdmin
    IsGuest = ($user.Name -eq 'Guest')
    UserMayChangePassword = $user.UserMayChangePassword
}} | ConvertTo-Json -Depth 2 -Compress
"#, username.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "null" || trimmed.is_empty() {
        return Ok(None);
    }

    let users = parse_users_with_security(&format!("[{}]", trimmed))?;
    Ok(users.into_iter().next())
}

/// Find users with excessive privileges
pub async fn find_users_with_admin_privileges(client: &WinRmClient) -> Result<Vec<UserSecurityInfo>> {
    let users = collect_users_with_security(client).await?;
    Ok(users.into_iter().filter(|u| u.is_admin).collect())
}

/// Find enabled user accounts that haven't logged in recently
pub async fn find_stale_accounts(client: &WinRmClient, days_threshold: u32) -> Result<Vec<UserSecurityInfo>> {
    let users = collect_users_with_security(client).await?;
    let threshold = Utc::now() - chrono::Duration::days(days_threshold as i64);

    Ok(users.into_iter()
        .filter(|u| {
            u.user.enabled &&
            u.user.last_logon.map(|d| d < threshold).unwrap_or(true)
        })
        .collect())
}

/// Find accounts with passwords that don't expire (potential security issue)
pub async fn find_non_expiring_passwords(client: &WinRmClient) -> Result<Vec<UserSecurityInfo>> {
    let users = collect_users_with_security(client).await?;
    Ok(users.into_iter()
        .filter(|u| u.user.enabled && !u.user.password_expires)
        .collect())
}

/// STIG-related user and group checks
pub mod stig_checks {
    use super::*;

    /// V-220735: Guest account must be disabled
    pub async fn check_guest_account_disabled(client: &WinRmClient) -> Result<bool> {
        let script = r#"
$guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
if ($guest) {
    if ($guest.Enabled) { 'false' } else { 'true' }
} else {
    'true'  # Guest account doesn't exist, which is fine
}
"#;
        let output = client.execute_powershell(script).await?;
        Ok(output.trim().to_lowercase() == "true")
    }

    /// V-220736: Guest account must be renamed
    pub async fn check_guest_account_renamed(client: &WinRmClient) -> Result<bool> {
        let script = r#"
$guest = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
if ($guest) {
    if ($guest.Name -ne 'Guest') { 'true' } else { 'false' }
} else {
    'true'  # No guest account
}
"#;
        let output = client.execute_powershell(script).await?;
        Ok(output.trim().to_lowercase() == "true")
    }

    /// V-220737: Administrator account must be renamed
    pub async fn check_admin_account_renamed(client: &WinRmClient) -> Result<bool> {
        let script = r#"
$admin = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
if ($admin) {
    if ($admin.Name -ne 'Administrator') { 'true' } else { 'false' }
} else {
    'true'
}
"#;
        let output = client.execute_powershell(script).await?;
        Ok(output.trim().to_lowercase() == "true")
    }

    /// V-220738: Only authorized accounts must be in Administrators group
    pub async fn check_administrators_group(
        client: &WinRmClient,
        allowed_members: &[&str],
    ) -> Result<(bool, Vec<String>)> {
        let members = get_administrators_group_members(client).await?;

        let unauthorized: Vec<String> = members.iter()
            .filter(|m| !allowed_members.iter().any(|a| m.contains(a)))
            .cloned()
            .collect();

        Ok((unauthorized.is_empty(), unauthorized))
    }

    /// V-220739: Only authorized accounts must have RDP access
    pub async fn check_rdp_users_group(
        client: &WinRmClient,
        allowed_members: &[&str],
    ) -> Result<(bool, Vec<String>)> {
        let members = get_rdp_users_group_members(client).await?;

        let unauthorized: Vec<String> = members.iter()
            .filter(|m| !allowed_members.iter().any(|a| m.contains(a)))
            .cloned()
            .collect();

        Ok((unauthorized.is_empty(), unauthorized))
    }

    /// V-220740: No accounts should have blank passwords
    pub async fn check_no_blank_passwords(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let users = collect_users_with_security(client).await?;

        let no_password_required: Vec<String> = users.iter()
            .filter(|u| u.user.enabled && !u.user.password_required)
            .map(|u| u.user.name.clone())
            .collect();

        Ok((no_password_required.is_empty(), no_password_required))
    }

    /// V-220741: Password must expire for all accounts
    pub async fn check_passwords_expire(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let non_expiring = find_non_expiring_passwords(client).await?;

        let non_compliant: Vec<String> = non_expiring.iter()
            .filter(|u| !u.is_guest) // Guest account is special case
            .map(|u| u.user.name.clone())
            .collect();

        Ok((non_compliant.is_empty(), non_compliant))
    }

    /// V-220742: Inactive accounts must be disabled after specified period
    pub async fn check_inactive_accounts_disabled(
        client: &WinRmClient,
        days_threshold: u32,
    ) -> Result<(bool, Vec<String>)> {
        let stale = find_stale_accounts(client, days_threshold).await?;

        let stale_names: Vec<String> = stale.iter()
            .map(|u| format!("{} (last logon: {:?})", u.user.name, u.user.last_logon))
            .collect();

        Ok((stale_names.is_empty(), stale_names))
    }

    /// Check all built-in accounts are properly configured
    pub async fn check_builtin_accounts(client: &WinRmClient) -> Result<Vec<(String, bool, String)>> {
        let mut results = Vec::new();

        // Check Guest
        let guest_disabled = check_guest_account_disabled(client).await?;
        results.push(("Guest account disabled".to_string(), guest_disabled,
            if guest_disabled { "Compliant".to_string() } else { "Guest account is enabled".to_string() }));

        let guest_renamed = check_guest_account_renamed(client).await?;
        results.push(("Guest account renamed".to_string(), guest_renamed,
            if guest_renamed { "Compliant".to_string() } else { "Guest account not renamed".to_string() }));

        // Check Administrator
        let admin_renamed = check_admin_account_renamed(client).await?;
        results.push(("Administrator account renamed".to_string(), admin_renamed,
            if admin_renamed { "Compliant".to_string() } else { "Administrator account not renamed".to_string() }));

        Ok(results)
    }
}
