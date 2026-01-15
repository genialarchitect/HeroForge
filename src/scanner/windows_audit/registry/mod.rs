//! Registry collection module for Windows audit scanning
//!
//! Collects registry keys and values from remote Windows systems for STIG compliance checking.

use anyhow::Result;
use super::types::{RegistryKey, RegistryValue, RegistryValueType};
use super::WinRmClient;

/// Security-relevant registry paths for STIG compliance
pub const SECURITY_REGISTRY_PATHS: &[&str] = &[
    // Password and Account Policies
    r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",

    // Network Security
    r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters",
    r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    r"HKLM:\SYSTEM\CurrentControlSet\Services\LDAP",

    // Audit Settings
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Audit",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",

    // Remote Desktop
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",

    // Windows Defender / Security
    r"HKLM:\SOFTWARE\Microsoft\Windows Defender",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Guard",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard",

    // Credential Guard
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\LSA\LsaCfgFlags",

    // BitLocker
    r"HKLM:\SOFTWARE\Policies\Microsoft\FVE",

    // SMB Settings
    r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",

    // PowerShell Logging
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",

    // Windows Update
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",

    // Internet Settings
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer",

    // Autoplay/Autorun
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",

    // Remote Assistance
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance",

    // Windows Firewall
    r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall",
    r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
    r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",

    // WinRM
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",

    // AppLocker
    r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2",

    // Secure Boot
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
];

/// Collect registry keys from a Windows system
pub async fn collect_registry_keys(client: &WinRmClient, paths: &[&str]) -> Result<Vec<RegistryKey>> {
    let mut results = Vec::new();

    for path in paths {
        match collect_single_key(client, path).await {
            Ok(Some(key)) => results.push(key),
            Ok(None) => {
                // Key doesn't exist, skip
                log::debug!("Registry key does not exist: {}", path);
            }
            Err(e) => {
                log::warn!("Failed to collect registry key {}: {}", path, e);
            }
        }
    }

    Ok(results)
}

/// Collect all security-relevant registry keys
pub async fn collect_security_registry(client: &WinRmClient) -> Result<Vec<RegistryKey>> {
    collect_registry_keys(client, SECURITY_REGISTRY_PATHS).await
}

/// Collect a single registry key with all its values
async fn collect_single_key(client: &WinRmClient, path: &str) -> Result<Option<RegistryKey>> {
    let script = format!(r#"
if (Test-Path '{}') {{
    $key = Get-Item '{}'
    $values = @()
    foreach ($valueName in $key.GetValueNames()) {{
        $valueData = $key.GetValue($valueName)
        $valueKind = $key.GetValueKind($valueName)
        $values += @{{
            Name = $valueName
            Type = $valueKind.ToString()
            Data = if ($valueData -is [byte[]]) {{
                [System.BitConverter]::ToString($valueData)
            }} else {{
                $valueData.ToString()
            }}
        }}
    }}
    @{{
        Path = '{}'
        Values = $values
    }} | ConvertTo-Json -Depth 5
}} else {{
    Write-Output 'KEY_NOT_FOUND'
}}
"#, path.replace("'", "''"), path.replace("'", "''"), path.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "KEY_NOT_FOUND" || trimmed.is_empty() {
        return Ok(None);
    }

    parse_registry_key_json(trimmed)
}

/// Parse JSON output from PowerShell into RegistryKey
fn parse_registry_key_json(json_str: &str) -> Result<Option<RegistryKey>> {
    let value: serde_json::Value = serde_json::from_str(json_str)?;

    let path = value.get("Path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if path.is_empty() {
        return Ok(None);
    }

    let values_array = value.get("Values")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let values: Vec<RegistryValue> = values_array.iter()
        .filter_map(|v| {
            let name = v.get("Name")?.as_str()?.to_string();
            let type_str = v.get("Type")?.as_str()?;
            let data = v.get("Data")?.as_str()?.to_string();

            Some(RegistryValue {
                name,
                value_type: parse_registry_type(type_str),
                data,
            })
        })
        .collect();

    Ok(Some(RegistryKey { path, values }))
}

/// Parse registry value type string
fn parse_registry_type(type_str: &str) -> RegistryValueType {
    match type_str.to_lowercase().as_str() {
        "string" | "reg_sz" => RegistryValueType::RegSz,
        "expandstring" | "reg_expand_sz" => RegistryValueType::RegExpandSz,
        "binary" | "reg_binary" => RegistryValueType::RegBinary,
        "dword" | "reg_dword" => RegistryValueType::RegDword,
        "qword" | "reg_qword" => RegistryValueType::RegQword,
        "multistring" | "reg_multi_sz" => RegistryValueType::RegMultiSz,
        "none" | "reg_none" => RegistryValueType::RegNone,
        _ => RegistryValueType::Unknown,
    }
}

/// Get a specific registry value
pub async fn get_registry_value(client: &WinRmClient, path: &str, value_name: &str) -> Result<Option<RegistryValue>> {
    let script = format!(r#"
$path = '{}'
$valueName = '{}'
if (Test-Path $path) {{
    $key = Get-Item $path
    if ($key.GetValueNames() -contains $valueName) {{
        $valueData = $key.GetValue($valueName)
        $valueKind = $key.GetValueKind($valueName)
        @{{
            Name = $valueName
            Type = $valueKind.ToString()
            Data = if ($valueData -is [byte[]]) {{
                [System.BitConverter]::ToString($valueData)
            }} else {{
                $valueData.ToString()
            }}
        }} | ConvertTo-Json
    }} else {{
        Write-Output 'VALUE_NOT_FOUND'
    }}
}} else {{
    Write-Output 'KEY_NOT_FOUND'
}}
"#, path.replace("'", "''"), value_name.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "KEY_NOT_FOUND" || trimmed == "VALUE_NOT_FOUND" || trimmed.is_empty() {
        return Ok(None);
    }

    let value: serde_json::Value = serde_json::from_str(trimmed)?;

    let name = value.get("Name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let type_str = value.get("Type")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let data = value.get("Data")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Some(RegistryValue {
        name,
        value_type: parse_registry_type(type_str),
        data,
    }))
}

/// Check if a registry value exists and matches expected value
pub async fn check_registry_value(
    client: &WinRmClient,
    path: &str,
    value_name: &str,
    expected: &str,
) -> Result<RegistryCheckResult> {
    match get_registry_value(client, path, value_name).await? {
        Some(value) => {
            let matches = value.data.trim() == expected.trim();
            Ok(RegistryCheckResult {
                exists: true,
                value: Some(value),
                matches_expected: matches,
            })
        }
        None => Ok(RegistryCheckResult {
            exists: false,
            value: None,
            matches_expected: false,
        }),
    }
}

/// Result of a registry value check
#[derive(Debug, Clone)]
pub struct RegistryCheckResult {
    pub exists: bool,
    pub value: Option<RegistryValue>,
    pub matches_expected: bool,
}

/// Check multiple registry values at once
pub async fn check_registry_values_batch(
    client: &WinRmClient,
    checks: &[RegistryCheck],
) -> Result<Vec<RegistryCheckResult>> {
    let mut results = Vec::new();

    for check in checks {
        let result = check_registry_value(client, &check.path, &check.value_name, &check.expected).await?;
        results.push(result);
    }

    Ok(results)
}

/// A registry check specification
#[derive(Debug, Clone)]
pub struct RegistryCheck {
    pub path: String,
    pub value_name: String,
    pub expected: String,
}

impl RegistryCheck {
    pub fn new(path: &str, value_name: &str, expected: &str) -> Self {
        Self {
            path: path.to_string(),
            value_name: value_name.to_string(),
            expected: expected.to_string(),
        }
    }
}

/// Common STIG-related registry checks
pub fn get_common_stig_registry_checks() -> Vec<RegistryCheck> {
    vec![
        // V-220697: Credential Guard must be enabled
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Control\LSA",
            "LsaCfgFlags",
            "1",
        ),
        // V-220698: SMBv1 must be disabled
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
            "0",
        ),
        // V-220699: WDigest Authentication must be disabled
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            "0",
        ),
        // V-220700: Remote host requires NTLMv2 authentication
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel",
            "5",
        ),
        // V-220701: Anonymous enumeration of shares must be restricted
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymous",
            "1",
        ),
        // V-220702: Anonymous SID/Name translation must be restricted
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "RestrictAnonymousSAM",
            "1",
        ),
        // V-220703: Auto logon must be disabled
        RegistryCheck::new(
            r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoAdminLogon",
            "0",
        ),
        // V-220704: LDAP channel binding must be enabled
        RegistryCheck::new(
            r"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
            "LDAPServerIntegrity",
            "2",
        ),
        // V-220705: PowerShell Script Block Logging must be enabled
        RegistryCheck::new(
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging",
            "1",
        ),
        // V-220706: User Account Control must be enabled
        RegistryCheck::new(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            "1",
        ),
        // V-220707: UAC must virtualize file and registry failures
        RegistryCheck::new(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableVirtualization",
            "1",
        ),
        // V-220708: UAC Admin Approval Mode must be enabled
        RegistryCheck::new(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "FilterAdministratorToken",
            "1",
        ),
    ]
}
