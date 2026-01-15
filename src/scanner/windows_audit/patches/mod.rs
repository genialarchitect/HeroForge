//! Patch collection module for Windows audit scanning
//!
//! Collects installed hotfixes, update history, and checks for missing critical updates.

use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use super::types::InstalledPatch;
use super::WinRmClient;

/// Windows Update configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateConfiguration {
    /// Automatic Update service status
    pub au_enabled: bool,
    /// Automatic Update options (1=disabled, 2=notify, 3=auto download, 4=auto install)
    pub au_options: u32,
    /// WSUS server URL if configured
    pub wsus_server: Option<String>,
    /// Target group for WSUS
    pub wsus_target_group: Option<String>,
    /// Whether to include Microsoft Update
    pub include_microsoft_update: bool,
    /// Scheduled install day (0=daily, 1-7=day of week)
    pub scheduled_install_day: u32,
    /// Scheduled install time (0-23 hour)
    pub scheduled_install_time: u32,
}

/// Windows Update history entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateHistoryEntry {
    pub title: String,
    pub description: Option<String>,
    pub date: Option<DateTime<Utc>>,
    pub operation: UpdateOperation,
    pub result_code: UpdateResultCode,
    pub support_url: Option<String>,
    pub update_id: Option<String>,
    pub categories: Vec<String>,
}

/// Update operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateOperation {
    Installation,
    Uninstallation,
    Other,
}

/// Update result code
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateResultCode {
    NotStarted,
    InProgress,
    Succeeded,
    SucceededWithErrors,
    Failed,
    Aborted,
}

/// Missing update information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MissingUpdate {
    pub title: String,
    pub description: Option<String>,
    pub kb_article_ids: Vec<String>,
    pub severity: Option<UpdateSeverity>,
    pub is_mandatory: bool,
    pub categories: Vec<String>,
    pub support_url: Option<String>,
    pub update_id: String,
    pub size_bytes: Option<u64>,
    pub release_date: Option<DateTime<Utc>>,
}

/// Update severity rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateSeverity {
    Critical,
    Important,
    Moderate,
    Low,
    Unspecified,
}

/// Patch compliance summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PatchComplianceSummary {
    pub total_installed: usize,
    pub missing_critical: usize,
    pub missing_important: usize,
    pub missing_other: usize,
    pub last_update_check: Option<DateTime<Utc>>,
    pub last_update_install: Option<DateTime<Utc>>,
    pub reboot_pending: bool,
    pub compliance_percentage: f32,
}

/// Parse hotfix list from PowerShell JSON output
pub fn parse_hotfix_list(json_output: &str) -> Result<Vec<InstalledPatch>> {
    let patches: Vec<InstalledPatch> = match serde_json::from_str(json_output) {
        Ok(p) => p,
        Err(_) => {
            // Try parsing as array of objects
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
                arr.iter()
                    .filter_map(|v| {
                        Some(InstalledPatch {
                            hotfix_id: v.get("HotFixID")?.as_str()?.to_string(),
                            description: v.get("Description").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            installed_on: parse_date_string(v.get("InstalledOn").and_then(|x| x.as_str())),
                            installed_by: v.get("InstalledBy").and_then(|x| x.as_str()).map(|s| s.to_string()),
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
    };
    Ok(patches)
}

/// Parse date string from PowerShell output
fn parse_date_string(date_str: Option<&str>) -> Option<DateTime<Utc>> {
    let s = date_str?;
    // Try various date formats and convert to DateTime<Utc>
    if let Ok(d) = NaiveDate::parse_from_str(s, "%m/%d/%Y") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0)?, Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0)?, Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%d/%m/%Y") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(d.and_hms_opt(0, 0, 0)?, Utc));
    }
    // Try ISO 8601 format
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    None
}

/// Collect all installed hotfixes from a Windows system
pub async fn collect_installed_patches(client: &WinRmClient) -> Result<Vec<InstalledPatch>> {
    let script = r#"
Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    parse_hotfix_list(trimmed)
}

/// Get Windows Update history
pub async fn get_update_history(client: &WinRmClient, max_entries: usize) -> Result<Vec<UpdateHistoryEntry>> {
    let script = format!(r#"
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$History = $Searcher.QueryHistory(0, {})
$results = @()
foreach ($entry in $History) {{
    $results += @{{
        Title = $entry.Title
        Description = $entry.Description
        Date = $entry.Date.ToString("o")
        Operation = $entry.Operation
        ResultCode = $entry.ResultCode
        SupportUrl = $entry.SupportUrl
        UpdateIdentity = $entry.UpdateIdentity.UpdateID
        Categories = @($entry.Categories | ForEach-Object {{ $_.Name }})
    }}
}}
$results | ConvertTo-Json -Depth 3 -Compress
"#, max_entries);

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_update_history(trimmed)
}

/// Parse update history JSON
fn parse_update_history(json_output: &str) -> Result<Vec<UpdateHistoryEntry>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let entries = arr.iter()
            .filter_map(|v| {
                Some(UpdateHistoryEntry {
                    title: v.get("Title")?.as_str()?.to_string(),
                    description: v.get("Description").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    date: v.get("Date").and_then(|x| x.as_str()).and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&Utc)),
                    operation: parse_operation(v.get("Operation").and_then(|x| x.as_i64()).unwrap_or(0) as u32),
                    result_code: parse_result_code(v.get("ResultCode").and_then(|x| x.as_i64()).unwrap_or(0) as u32),
                    support_url: v.get("SupportUrl").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    update_id: v.get("UpdateIdentity").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    categories: v.get("Categories")
                        .and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                })
            })
            .collect();
        Ok(entries)
    } else {
        Ok(Vec::new())
    }
}

fn parse_operation(code: u32) -> UpdateOperation {
    match code {
        1 => UpdateOperation::Installation,
        2 => UpdateOperation::Uninstallation,
        _ => UpdateOperation::Other,
    }
}

fn parse_result_code(code: u32) -> UpdateResultCode {
    match code {
        0 => UpdateResultCode::NotStarted,
        1 => UpdateResultCode::InProgress,
        2 => UpdateResultCode::Succeeded,
        3 => UpdateResultCode::SucceededWithErrors,
        4 => UpdateResultCode::Failed,
        5 => UpdateResultCode::Aborted,
        _ => UpdateResultCode::Failed,
    }
}

/// Check for missing Windows updates
pub async fn check_missing_updates(client: &WinRmClient, include_optional: bool) -> Result<Vec<MissingUpdate>> {
    let criteria = if include_optional {
        "IsInstalled=0"
    } else {
        "IsInstalled=0 and IsHidden=0"
    };

    let script = format!(r#"
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
try {{
    $SearchResult = $Searcher.Search("{}")
    $results = @()
    foreach ($Update in $SearchResult.Updates) {{
        $kbs = @($Update.KBArticleIDs)
        $cats = @($Update.Categories | ForEach-Object {{ $_.Name }})
        $results += @{{
            Title = $Update.Title
            Description = $Update.Description
            KBArticleIDs = $kbs
            MsrcSeverity = $Update.MsrcSeverity
            IsMandatory = $Update.IsMandatory
            Categories = $cats
            SupportUrl = $Update.SupportUrl
            UpdateID = $Update.Identity.UpdateID
            MaxDownloadSize = $Update.MaxDownloadSize
            LastDeploymentChangeTime = if ($Update.LastDeploymentChangeTime) {{ $Update.LastDeploymentChangeTime.ToString("o") }} else {{ $null }}
        }}
    }}
    $results | ConvertTo-Json -Depth 3 -Compress
}} catch {{
    Write-Output "[]"
}}
"#, criteria);

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_missing_updates(trimmed)
}

/// Parse missing updates JSON
fn parse_missing_updates(json_output: &str) -> Result<Vec<MissingUpdate>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let updates = arr.iter()
            .filter_map(|v| {
                Some(MissingUpdate {
                    title: v.get("Title")?.as_str()?.to_string(),
                    description: v.get("Description").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    kb_article_ids: v.get("KBArticleIDs")
                        .and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| format!("KB{}", s))).collect())
                        .unwrap_or_default(),
                    severity: v.get("MsrcSeverity").and_then(|x| x.as_str()).map(parse_severity),
                    is_mandatory: v.get("IsMandatory").and_then(|x| x.as_bool()).unwrap_or(false),
                    categories: v.get("Categories")
                        .and_then(|x| x.as_array())
                        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    support_url: v.get("SupportUrl").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    update_id: v.get("UpdateID")?.as_str()?.to_string(),
                    size_bytes: v.get("MaxDownloadSize").and_then(|x| x.as_u64()),
                    release_date: v.get("LastDeploymentChangeTime")
                        .and_then(|x| x.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.with_timezone(&Utc)),
                })
            })
            .collect();
        Ok(updates)
    } else {
        Ok(Vec::new())
    }
}

fn parse_severity(s: &str) -> UpdateSeverity {
    match s.to_lowercase().as_str() {
        "critical" => UpdateSeverity::Critical,
        "important" => UpdateSeverity::Important,
        "moderate" => UpdateSeverity::Moderate,
        "low" => UpdateSeverity::Low,
        _ => UpdateSeverity::Unspecified,
    }
}

/// Get Windows Update configuration settings
pub async fn get_update_configuration(client: &WinRmClient) -> Result<UpdateConfiguration> {
    let script = r#"
$auKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

$config = @{
    AUEnabled = $false
    AUOptions = 0
    WsusServer = $null
    WsusTargetGroup = $null
    IncludeMicrosoftUpdate = $false
    ScheduledInstallDay = 0
    ScheduledInstallTime = 3
}

if (Test-Path $auKey) {
    $au = Get-ItemProperty $auKey -ErrorAction SilentlyContinue
    if ($au.NoAutoUpdate -eq 0 -or $au.NoAutoUpdate -eq $null) { $config.AUEnabled = $true }
    if ($au.AUOptions) { $config.AUOptions = $au.AUOptions }
    if ($au.ScheduledInstallDay) { $config.ScheduledInstallDay = $au.ScheduledInstallDay }
    if ($au.ScheduledInstallTime) { $config.ScheduledInstallTime = $au.ScheduledInstallTime }
}

if (Test-Path $wuKey) {
    $wu = Get-ItemProperty $wuKey -ErrorAction SilentlyContinue
    if ($wu.WUServer) { $config.WsusServer = $wu.WUServer }
    if ($wu.TargetGroup) { $config.WsusTargetGroup = $wu.TargetGroup }
}

# Check Microsoft Update opt-in
$ServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$config.IncludeMicrosoftUpdate = ($ServiceManager.Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }) -ne $null

$config | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(UpdateConfiguration {
            au_enabled: false,
            au_options: 0,
            wsus_server: None,
            wsus_target_group: None,
            include_microsoft_update: false,
            scheduled_install_day: 0,
            scheduled_install_time: 3,
        });
    }

    parse_update_configuration(trimmed)
}

fn parse_update_configuration(json_output: &str) -> Result<UpdateConfiguration> {
    let v: serde_json::Value = serde_json::from_str(json_output)?;

    Ok(UpdateConfiguration {
        au_enabled: v.get("AUEnabled").and_then(|x| x.as_bool()).unwrap_or(false),
        au_options: v.get("AUOptions").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        wsus_server: v.get("WsusServer").and_then(|x| x.as_str()).map(|s| s.to_string()),
        wsus_target_group: v.get("WsusTargetGroup").and_then(|x| x.as_str()).map(|s| s.to_string()),
        include_microsoft_update: v.get("IncludeMicrosoftUpdate").and_then(|x| x.as_bool()).unwrap_or(false),
        scheduled_install_day: v.get("ScheduledInstallDay").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        scheduled_install_time: v.get("ScheduledInstallTime").and_then(|x| x.as_u64()).unwrap_or(3) as u32,
    })
}

/// Check if a specific KB is installed
pub async fn check_kb_installed(client: &WinRmClient, kb_id: &str) -> Result<bool> {
    let kb_clean = kb_id.trim_start_matches("KB").trim_start_matches("kb");
    let script = format!(r#"
$kb = Get-HotFix -Id "KB{}" -ErrorAction SilentlyContinue
if ($kb) {{ "true" }} else {{ "false" }}
"#, kb_clean);

    let output = client.execute_powershell(&script).await?;
    Ok(output.trim().to_lowercase() == "true")
}

/// Check if reboot is pending after updates
pub async fn check_reboot_pending(client: &WinRmClient) -> Result<bool> {
    let script = r#"
$rebootPending = $false

# Check Component Based Servicing
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $rebootPending = $true
}

# Check Windows Update
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $rebootPending = $true
}

# Check Pending File Rename Operations
$pfro = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($pfro.PendingFileRenameOperations) {
    $rebootPending = $true
}

if ($rebootPending) { "true" } else { "false" }
"#;

    let output = client.execute_powershell(script).await?;
    Ok(output.trim().to_lowercase() == "true")
}

/// Get patch compliance summary
pub async fn get_patch_compliance_summary(client: &WinRmClient) -> Result<PatchComplianceSummary> {
    let installed = collect_installed_patches(client).await?;
    let missing = check_missing_updates(client, false).await?;
    let reboot_pending = check_reboot_pending(client).await?;

    let missing_critical = missing.iter()
        .filter(|u| matches!(u.severity, Some(UpdateSeverity::Critical)))
        .count();
    let missing_important = missing.iter()
        .filter(|u| matches!(u.severity, Some(UpdateSeverity::Important)))
        .count();
    let missing_other = missing.len() - missing_critical - missing_important;

    // Calculate compliance percentage
    let total_required = installed.len() + missing_critical + missing_important;
    let compliance_percentage = if total_required > 0 {
        (installed.len() as f32 / total_required as f32) * 100.0
    } else {
        100.0
    };

    // Get last update times
    let last_update_install = installed.iter()
        .filter_map(|p| p.installed_on)
        .max();

    Ok(PatchComplianceSummary {
        total_installed: installed.len(),
        missing_critical,
        missing_important,
        missing_other,
        last_update_check: None, // Would need additional query
        last_update_install,
        reboot_pending,
        compliance_percentage,
    })
}

/// STIG-related patch checks
pub mod stig_checks {
    use super::*;

    /// V-220724: Check if latest cumulative update is installed (within 60 days)
    pub async fn check_cumulative_update_current(client: &WinRmClient, max_age_days: i64) -> Result<bool> {
        let history = get_update_history(client, 100).await?;
        let cutoff = Utc::now() - chrono::Duration::days(max_age_days);

        // Look for cumulative updates in recent history
        let has_recent_cu = history.iter().any(|entry| {
            if let Some(date) = entry.date {
                if date > cutoff {
                    let title_lower = entry.title.to_lowercase();
                    return title_lower.contains("cumulative update") ||
                           title_lower.contains("security update") ||
                           title_lower.contains("monthly rollup");
                }
            }
            false
        });

        Ok(has_recent_cu)
    }

    /// V-220725: Check that automatic updates are enabled
    pub async fn check_automatic_updates_enabled(client: &WinRmClient) -> Result<bool> {
        let config = get_update_configuration(client).await?;
        // AU Options: 2=Notify, 3=Auto Download, 4=Auto Install
        Ok(config.au_enabled && config.au_options >= 3)
    }

    /// Check for specific security updates required by STIG
    pub async fn check_required_security_updates(
        client: &WinRmClient,
        required_kbs: &[&str],
    ) -> Result<Vec<(String, bool)>> {
        let mut results = Vec::new();

        for kb in required_kbs {
            let installed = check_kb_installed(client, kb).await?;
            results.push((kb.to_string(), installed));
        }

        Ok(results)
    }
}
