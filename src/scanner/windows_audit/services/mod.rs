//! Windows services collection module for Windows audit scanning
//!
//! Collects service configuration, permissions, and security settings for STIG compliance.

use anyhow::Result;
use super::types::{WindowsService, ServiceStatus, ServiceStartType};
use super::WinRmClient;

/// Extended service information with security details
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceSecurityInfo {
    pub service: WindowsService,
    pub binary_path: Option<String>,
    pub service_account: String,
    pub permissions: Vec<ServicePermission>,
    pub failure_actions: Option<FailureActions>,
    pub is_unquoted_path: bool,
    pub is_writeable_path: bool,
}

/// Service permission entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServicePermission {
    pub identity: String,
    pub access_rights: Vec<String>,
}

/// Service failure actions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FailureActions {
    pub reset_period_seconds: u32,
    pub reboot_message: Option<String>,
    pub command: Option<String>,
    pub actions: Vec<FailureAction>,
}

/// Individual failure action
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FailureAction {
    pub action_type: FailureActionType,
    pub delay_ms: u32,
}

/// Failure action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FailureActionType {
    None,
    Restart,
    Reboot,
    RunCommand,
}

/// Service startup configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceStartupConfig {
    pub delayed_auto_start: bool,
    pub trigger_start: bool,
    pub pre_shutdown_timeout_ms: Option<u32>,
}

/// Parse service list from PowerShell JSON output
pub fn parse_service_list(json_output: &str) -> Result<Vec<WindowsService>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let services = arr.iter()
            .filter_map(|v| {
                Some(WindowsService {
                    name: v.get("Name")?.as_str()?.to_string(),
                    display_name: v.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    status: parse_service_status(v.get("Status").and_then(|x| x.as_str()).unwrap_or("")),
                    start_type: parse_start_type(v.get("StartType").and_then(|x| x.as_str()).unwrap_or("")),
                    account: v.get("StartName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    path: v.get("PathName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                })
            })
            .collect();
        Ok(services)
    } else {
        Ok(Vec::new())
    }
}

fn parse_service_status(s: &str) -> ServiceStatus {
    match s.to_lowercase().as_str() {
        "running" => ServiceStatus::Running,
        "stopped" => ServiceStatus::Stopped,
        "paused" => ServiceStatus::Paused,
        "startpending" | "start pending" => ServiceStatus::StartPending,
        "stoppending" | "stop pending" => ServiceStatus::StopPending,
        _ => ServiceStatus::Unknown,
    }
}

fn parse_start_type(s: &str) -> ServiceStartType {
    match s.to_lowercase().as_str() {
        "automatic" | "auto" => ServiceStartType::Automatic,
        "automaticdelayed" | "automatic (delayed start)" | "auto (delayed)" => ServiceStartType::AutomaticDelayed,
        "manual" => ServiceStartType::Manual,
        "disabled" => ServiceStartType::Disabled,
        _ => ServiceStartType::Unknown,
    }
}

/// Collect all services with basic information
pub async fn collect_services(client: &WinRmClient) -> Result<Vec<WindowsService>> {
    let script = r#"
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    ForEach-Object {
        @{
            Name = $_.Name
            DisplayName = $_.DisplayName
            Status = $_.State
            StartType = $_.StartMode
            StartName = $_.StartName
            PathName = $_.PathName
        }
    } | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    parse_service_list(trimmed)
}

/// Collect services with extended security information
pub async fn collect_services_with_security(client: &WinRmClient) -> Result<Vec<ServiceSecurityInfo>> {
    let script = r#"
$results = @()
$services = Get-CimInstance Win32_Service

foreach ($svc in $services) {
    $secInfo = @{
        Name = $svc.Name
        DisplayName = $svc.DisplayName
        Status = $svc.State
        StartType = $svc.StartMode
        StartName = $svc.StartName
        PathName = $svc.PathName
        Permissions = @()
        IsUnquotedPath = $false
        IsWriteablePath = $false
    }

    # Check for unquoted service path vulnerability
    if ($svc.PathName -and $svc.PathName -match '^[^"].*\s.*\.exe') {
        if ($svc.PathName -notmatch '^"') {
            $secInfo.IsUnquotedPath = $true
        }
    }

    # Check if service binary path is writeable
    if ($svc.PathName) {
        $binPath = $svc.PathName -replace '"','' -split ' ' | Select-Object -First 1
        if (Test-Path $binPath) {
            try {
                $acl = Get-Acl $binPath -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match 'Users|Everyone|Authenticated Users' -and
                        $ace.FileSystemRights -match 'Write|Modify|FullControl') {
                        $secInfo.IsWriteablePath = $true
                        break
                    }
                }
            } catch {}
        }
    }

    # Get service permissions via sc.exe sdshow
    $sdOutput = sc.exe sdshow $svc.Name 2>$null
    if ($sdOutput -and $sdOutput -notmatch 'FAILED') {
        $secInfo.SDDL = $sdOutput -join ''
    }

    $results += $secInfo
}

$results | ConvertTo-Json -Depth 3 -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_services_with_security(trimmed)
}

fn parse_services_with_security(json_output: &str) -> Result<Vec<ServiceSecurityInfo>> {
    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(json_output) {
        let services = arr.iter()
            .filter_map(|v| {
                let service = WindowsService {
                    name: v.get("Name")?.as_str()?.to_string(),
                    display_name: v.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    status: parse_service_status(v.get("Status").and_then(|x| x.as_str()).unwrap_or("")),
                    start_type: parse_start_type(v.get("StartType").and_then(|x| x.as_str()).unwrap_or("")),
                    account: v.get("StartName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                    path: v.get("PathName").and_then(|x| x.as_str()).map(|s| s.to_string()),
                };

                Some(ServiceSecurityInfo {
                    binary_path: service.path.clone(),
                    service_account: service.account.clone().unwrap_or_else(|| "LocalSystem".to_string()),
                    permissions: Vec::new(), // Would need SDDL parsing
                    failure_actions: None,
                    is_unquoted_path: v.get("IsUnquotedPath").and_then(|x| x.as_bool()).unwrap_or(false),
                    is_writeable_path: v.get("IsWriteablePath").and_then(|x| x.as_bool()).unwrap_or(false),
                    service,
                })
            })
            .collect();
        Ok(services)
    } else {
        Ok(Vec::new())
    }
}

/// Get detailed information about a specific service
pub async fn get_service_detail(client: &WinRmClient, service_name: &str) -> Result<Option<ServiceSecurityInfo>> {
    let script = format!(r#"
$svc = Get-CimInstance Win32_Service -Filter "Name='{}'"
if (-not $svc) {{ Write-Output 'null'; exit }}

$result = @{{
    Name = $svc.Name
    DisplayName = $svc.DisplayName
    Description = $svc.Description
    Status = $svc.State
    StartType = $svc.StartMode
    StartName = $svc.StartName
    PathName = $svc.PathName
    ProcessId = $svc.ProcessId
    ExitCode = $svc.ExitCode
    ServiceType = $svc.ServiceType
    AcceptPause = $svc.AcceptPause
    AcceptStop = $svc.AcceptStop
    DesktopInteract = $svc.DesktopInteract
    ErrorControl = $svc.ErrorControl
    IsUnquotedPath = $false
    IsWriteablePath = $false
    FailureActions = $null
}}

# Check for unquoted service path
if ($svc.PathName -and $svc.PathName -match '^[^"].*\s.*\.exe' -and $svc.PathName -notmatch '^"') {{
    $result.IsUnquotedPath = $true
}}

# Get failure actions
$qfailure = sc.exe qfailure $svc.Name 2>$null
if ($qfailure) {{
    $result.FailureActionsRaw = $qfailure -join "`n"
}}

# Get service SDDL
$sdshow = sc.exe sdshow $svc.Name 2>$null
if ($sdshow -and $sdshow -notmatch 'FAILED') {{
    $result.SDDL = $sdshow -join ''
}}

# Check binary permissions
if ($svc.PathName) {{
    $binPath = $svc.PathName -replace '"','' -split ' ' | Select-Object -First 1
    if (Test-Path $binPath) {{
        try {{
            $acl = Get-Acl $binPath -ErrorAction SilentlyContinue
            $result.BinaryPermissions = @()
            foreach ($ace in $acl.Access) {{
                $result.BinaryPermissions += @{{
                    Identity = $ace.IdentityReference.ToString()
                    Rights = $ace.FileSystemRights.ToString()
                    Type = $ace.AccessControlType.ToString()
                }}
                if ($ace.IdentityReference -match 'Users|Everyone|Authenticated Users' -and
                    $ace.FileSystemRights -match 'Write|Modify|FullControl') {{
                    $result.IsWriteablePath = $true
                }}
            }}
        }} catch {{}}
    }}
}}

$result | ConvertTo-Json -Depth 3 -Compress
"#, service_name.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "null" || trimmed.is_empty() {
        return Ok(None);
    }

    let v: serde_json::Value = serde_json::from_str(trimmed)?;

    let service = WindowsService {
        name: v.get("Name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        display_name: v.get("DisplayName").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        status: parse_service_status(v.get("Status").and_then(|x| x.as_str()).unwrap_or("")),
        start_type: parse_start_type(v.get("StartType").and_then(|x| x.as_str()).unwrap_or("")),
        account: v.get("StartName").and_then(|x| x.as_str()).map(|s| s.to_string()),
        path: v.get("PathName").and_then(|x| x.as_str()).map(|s| s.to_string()),
    };

    let permissions = v.get("BinaryPermissions")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some(ServicePermission {
                        identity: p.get("Identity")?.as_str()?.to_string(),
                        access_rights: vec![p.get("Rights")?.as_str()?.to_string()],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(ServiceSecurityInfo {
        binary_path: service.path.clone(),
        service_account: service.account.clone().unwrap_or_else(|| "LocalSystem".to_string()),
        permissions,
        failure_actions: None,
        is_unquoted_path: v.get("IsUnquotedPath").and_then(|x| x.as_bool()).unwrap_or(false),
        is_writeable_path: v.get("IsWriteablePath").and_then(|x| x.as_bool()).unwrap_or(false),
        service,
    }))
}

/// Get services that should be disabled per STIG
pub async fn get_stig_disabled_services(client: &WinRmClient) -> Result<Vec<WindowsService>> {
    // Services that should be disabled per Windows Server STIGs
    let should_be_disabled = vec![
        "Browser",           // Computer Browser
        "IISADMIN",          // IIS Admin Service
        "W3SVC",             // World Wide Web Publishing Service
        "FTP",               // FTP Publishing Service
        "SMTPSVC",           // Simple Mail Transfer Protocol
        "TelnetServer",      // Telnet
        "SharedAccess",      // Internet Connection Sharing
        "RemoteRegistry",    // Remote Registry
        "SNMP",              // Simple Network Management Protocol
        "SNMPTRAP",          // SNMP Trap
        "simptcp",           // Simple TCP/IP Services
        "WMSvc",             // Web Management Service
        "wuauserv",          // Windows Update (in some high-security environments)
        "XblAuthManager",    // Xbox Live Auth Manager
        "XblGameSave",       // Xbox Live Game Save
        "XboxNetApiSvc",     // Xbox Live Networking Service
        "lfsvc",             // Geolocation Service
        "MapsBroker",        // Downloaded Maps Manager
        "RetailDemo",        // Retail Demo Service
    ];

    let filter = should_be_disabled.iter()
        .map(|s| format!("Name='{}'", s))
        .collect::<Vec<_>>()
        .join(" OR ");

    let script = format!(r#"
$services = Get-CimInstance Win32_Service -Filter "{}"
$results = @()
foreach ($svc in $services) {{
    if ($svc.StartMode -ne 'Disabled') {{
        $results += @{{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = $svc.State
            StartType = $svc.StartMode
            StartName = $svc.StartName
            PathName = $svc.PathName
        }}
    }}
}}
$results | ConvertTo-Json -Compress
"#, filter);

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_service_list(trimmed)
}

/// Find services with unquoted paths (privilege escalation vulnerability)
pub async fn find_unquoted_service_paths(client: &WinRmClient) -> Result<Vec<WindowsService>> {
    let script = r#"
$results = @()
$services = Get-CimInstance Win32_Service | Where-Object { $_.PathName -ne $null }

foreach ($svc in $services) {
    $path = $svc.PathName
    # Check if path contains spaces and is not quoted
    if ($path -match '^[^"].*\s.*\.exe' -and $path -notmatch '^"') {
        $results += @{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Status = $svc.State
            StartType = $svc.StartMode
            StartName = $svc.StartName
            PathName = $svc.PathName
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

    parse_service_list(trimmed)
}

/// Find services with weak permissions
pub async fn find_weak_service_permissions(client: &WinRmClient) -> Result<Vec<ServiceSecurityInfo>> {
    let services = collect_services_with_security(client).await?;

    Ok(services.into_iter()
        .filter(|s| s.is_unquoted_path || s.is_writeable_path)
        .collect())
}

/// Find services running as domain accounts (potential credential exposure)
pub async fn find_domain_account_services(client: &WinRmClient) -> Result<Vec<WindowsService>> {
    let script = r#"
$results = @()
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.StartName -ne $null -and
    $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT SERVICE|LocalService|NetworkService|.\\.*)$'
}

foreach ($svc in $services) {
    $results += @{
        Name = $svc.Name
        DisplayName = $svc.DisplayName
        Status = $svc.State
        StartType = $svc.StartMode
        StartName = $svc.StartName
        PathName = $svc.PathName
    }
}
$results | ConvertTo-Json -Compress
"#;

    let output = client.execute_powershell(script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    parse_service_list(trimmed)
}

/// Check if a specific service is running with expected configuration
pub async fn check_service_status(
    client: &WinRmClient,
    service_name: &str,
    expected_status: ServiceStatus,
    expected_start_type: ServiceStartType,
) -> Result<ServiceComplianceResult> {
    let services = collect_services(client).await?;

    let service = services.iter().find(|s| s.name.eq_ignore_ascii_case(service_name));

    match service {
        Some(svc) => {
            let status_compliant = svc.status == expected_status;
            let start_type_compliant = svc.start_type == expected_start_type;

            Ok(ServiceComplianceResult {
                exists: true,
                service: Some(svc.clone()),
                status_compliant,
                start_type_compliant,
                overall_compliant: status_compliant && start_type_compliant,
            })
        }
        None => Ok(ServiceComplianceResult {
            exists: false,
            service: None,
            status_compliant: false,
            start_type_compliant: false,
            overall_compliant: false,
        }),
    }
}

/// Service compliance check result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceComplianceResult {
    pub exists: bool,
    pub service: Option<WindowsService>,
    pub status_compliant: bool,
    pub start_type_compliant: bool,
    pub overall_compliant: bool,
}

/// STIG-related service checks
pub mod stig_checks {
    use super::*;

    /// V-220726: Fax Service must be disabled
    pub async fn check_fax_service_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "Fax", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220727: Microsoft FTP Service must be disabled unless required
    pub async fn check_ftp_service_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "FTPSVC", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220728: IIS Admin Service must be disabled unless required
    pub async fn check_iisadmin_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "IISADMIN", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220729: Print Spooler must not be running on domain controllers
    pub async fn check_print_spooler(client: &WinRmClient, is_domain_controller: bool) -> Result<bool> {
        if !is_domain_controller {
            return Ok(true); // Not applicable
        }
        let result = check_service_status(client, "Spooler", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220730: Remote Registry service should be disabled
    pub async fn check_remote_registry_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "RemoteRegistry", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220731: Simple TCP/IP Services must be disabled
    pub async fn check_simptcp_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "simptcp", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220732: SNMP Service must be disabled unless required
    pub async fn check_snmp_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "SNMP", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220733: Telnet must not be installed
    pub async fn check_telnet_disabled(client: &WinRmClient) -> Result<bool> {
        let result = check_service_status(client, "TlntSvr", ServiceStatus::Stopped, ServiceStartType::Disabled).await?;
        Ok(!result.exists || result.overall_compliant)
    }

    /// V-220734: Windows Remote Management (WinRM) must be securely configured
    pub async fn check_winrm_secure(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let script = r#"
$issues = @()

# Check if WinRM is using HTTPS
$listeners = winrm enumerate winrm/config/listener 2>$null
if ($listeners -notmatch 'Transport = HTTPS') {
    $issues += "WinRM not configured for HTTPS"
}

# Check for AllowUnencrypted
$service = winrm get winrm/config/service 2>$null
if ($service -match 'AllowUnencrypted = true') {
    $issues += "WinRM allows unencrypted traffic"
}

# Check authentication methods
$auth = winrm get winrm/config/service/auth 2>$null
if ($auth -match 'Basic = true') {
    $issues += "WinRM allows Basic authentication"
}

$issues | ConvertTo-Json -Compress
"#;

        let output = client.execute_powershell(script).await?;
        let trimmed = output.trim();

        if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
            return Ok((true, Vec::new()));
        }

        let issues: Vec<String> = serde_json::from_str(trimmed).unwrap_or_default();
        Ok((issues.is_empty(), issues))
    }

    /// Check all services that should be disabled per STIG
    pub async fn check_all_disabled_services(client: &WinRmClient) -> Result<Vec<(String, bool)>> {
        let non_compliant = get_stig_disabled_services(client).await?;

        let should_be_disabled = vec![
            "Fax", "FTPSVC", "IISADMIN", "simptcp", "SNMP", "SNMPTRAP",
            "TlntSvr", "Browser", "RemoteRegistry"
        ];

        let mut results = Vec::new();
        for service_name in should_be_disabled {
            let compliant = !non_compliant.iter().any(|s| s.name.eq_ignore_ascii_case(service_name));
            results.push((service_name.to_string(), compliant));
        }

        Ok(results)
    }
}
