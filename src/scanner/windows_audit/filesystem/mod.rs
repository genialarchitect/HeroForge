//! Windows filesystem ACL collection module for Windows audit scanning
//!
//! Collects file/folder permissions and auditing settings for STIG compliance.

use anyhow::Result;
use super::WinRmClient;

/// File ACL information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileAcl {
    pub path: String,
    pub owner: String,
    pub group: String,
    pub access_rules: Vec<AccessRule>,
    pub audit_rules: Vec<AuditRule>,
    pub sddl: Option<String>,
}

/// Access control rule
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessRule {
    pub identity: String,
    pub access_type: AccessControlType,
    pub file_rights: FileSystemRights,
    pub inheritance_flags: InheritanceFlags,
    pub propagation_flags: PropagationFlags,
    pub is_inherited: bool,
}

/// Audit rule for file auditing
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRule {
    pub identity: String,
    pub file_rights: FileSystemRights,
    pub audit_flags: AuditFlags,
    pub inheritance_flags: InheritanceFlags,
}

/// Access control type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AccessControlType {
    Allow,
    Deny,
}

/// File system rights (simplified)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSystemRights {
    pub full_control: bool,
    pub modify: bool,
    pub read_execute: bool,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub change_permissions: bool,
    pub take_ownership: bool,
    pub raw_value: String,
}

/// Inheritance flags
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InheritanceFlags {
    pub container_inherit: bool,
    pub object_inherit: bool,
}

/// Propagation flags
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PropagationFlags {
    pub inherit_only: bool,
    pub no_propagate_inherit: bool,
}

/// Audit flags
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditFlags {
    pub success: bool,
    pub failure: bool,
}

/// Sensitive file paths for STIG compliance
pub const SENSITIVE_FILE_PATHS: &[&str] = &[
    r"C:\Windows\System32\config",
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\winevt\Logs",
    r"C:\Windows\repair",
    r"C:\Windows\System32\GroupPolicy",
    r"C:\ProgramData\Microsoft\Crypto",
    r"C:\Users\Default",
    r"C:\Windows\System32\Tasks",
    r"C:\Windows\Temp",
];

/// Collect file ACLs for specified paths
pub async fn collect_file_acls(client: &WinRmClient, paths: &[&str]) -> Result<Vec<FileAcl>> {
    let mut results = Vec::new();

    for path in paths {
        match get_file_acl(client, path).await {
            Ok(Some(acl)) => results.push(acl),
            Ok(None) => {
                log::debug!("Path does not exist or access denied: {}", path);
            }
            Err(e) => {
                log::warn!("Failed to get ACL for {}: {}", path, e);
            }
        }
    }

    Ok(results)
}

/// Get ACL for a single file or folder
pub async fn get_file_acl(client: &WinRmClient, path: &str) -> Result<Option<FileAcl>> {
    let script = format!(r#"
$path = '{}'
if (-not (Test-Path $path)) {{
    Write-Output 'PATH_NOT_FOUND'
    exit
}}

try {{
    $acl = Get-Acl $path -ErrorAction Stop

    $accessRules = @()
    foreach ($rule in $acl.Access) {{
        $accessRules += @{{
            Identity = $rule.IdentityReference.Value
            AccessType = $rule.AccessControlType.ToString()
            FileRights = $rule.FileSystemRights.ToString()
            InheritanceFlags = $rule.InheritanceFlags.ToString()
            PropagationFlags = $rule.PropagationFlags.ToString()
            IsInherited = $rule.IsInherited
        }}
    }}

    $auditRules = @()
    foreach ($rule in $acl.Audit) {{
        $auditRules += @{{
            Identity = $rule.IdentityReference.Value
            FileRights = $rule.FileSystemRights.ToString()
            AuditFlags = $rule.AuditFlags.ToString()
            InheritanceFlags = $rule.InheritanceFlags.ToString()
        }}
    }}

    @{{
        Path = $path
        Owner = $acl.Owner
        Group = $acl.Group
        AccessRules = $accessRules
        AuditRules = $auditRules
        SDDL = $acl.Sddl
    }} | ConvertTo-Json -Depth 4 -Compress
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)"
}}
"#, path.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed == "PATH_NOT_FOUND" || trimmed.starts_with("ERROR:") || trimmed.is_empty() {
        return Ok(None);
    }

    parse_file_acl(trimmed)
}

fn parse_file_acl(json_output: &str) -> Result<Option<FileAcl>> {
    let v: serde_json::Value = serde_json::from_str(json_output)?;

    let access_rules = v.get("AccessRules")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(AccessRule {
                        identity: r.get("Identity")?.as_str()?.to_string(),
                        access_type: if r.get("AccessType")?.as_str()? == "Allow" {
                            AccessControlType::Allow
                        } else {
                            AccessControlType::Deny
                        },
                        file_rights: parse_file_rights(r.get("FileRights")?.as_str()?),
                        inheritance_flags: parse_inheritance_flags(r.get("InheritanceFlags").and_then(|x| x.as_str()).unwrap_or("")),
                        propagation_flags: parse_propagation_flags(r.get("PropagationFlags").and_then(|x| x.as_str()).unwrap_or("")),
                        is_inherited: r.get("IsInherited").and_then(|x| x.as_bool()).unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let audit_rules = v.get("AuditRules")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let audit_str = r.get("AuditFlags")?.as_str()?;
                    Some(AuditRule {
                        identity: r.get("Identity")?.as_str()?.to_string(),
                        file_rights: parse_file_rights(r.get("FileRights")?.as_str()?),
                        audit_flags: AuditFlags {
                            success: audit_str.contains("Success"),
                            failure: audit_str.contains("Failure"),
                        },
                        inheritance_flags: parse_inheritance_flags(r.get("InheritanceFlags").and_then(|x| x.as_str()).unwrap_or("")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(FileAcl {
        path: v.get("Path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        owner: v.get("Owner").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        group: v.get("Group").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        access_rules,
        audit_rules,
        sddl: v.get("SDDL").and_then(|x| x.as_str()).map(|s| s.to_string()),
    }))
}

fn parse_file_rights(rights_str: &str) -> FileSystemRights {
    let s = rights_str.to_lowercase();
    FileSystemRights {
        full_control: s.contains("fullcontrol"),
        modify: s.contains("modify"),
        read_execute: s.contains("readandexecute"),
        read: s.contains("read") && !s.contains("readandexecute"),
        write: s.contains("write") && !s.contains("readandexecute"),
        delete: s.contains("delete"),
        change_permissions: s.contains("changepermissions"),
        take_ownership: s.contains("takeownership"),
        raw_value: rights_str.to_string(),
    }
}

fn parse_inheritance_flags(flags_str: &str) -> InheritanceFlags {
    InheritanceFlags {
        container_inherit: flags_str.contains("ContainerInherit"),
        object_inherit: flags_str.contains("ObjectInherit"),
    }
}

fn parse_propagation_flags(flags_str: &str) -> PropagationFlags {
    PropagationFlags {
        inherit_only: flags_str.contains("InheritOnly"),
        no_propagate_inherit: flags_str.contains("NoPropagateInherit"),
    }
}

/// Collect ACLs for sensitive STIG paths
pub async fn collect_sensitive_file_acls(client: &WinRmClient) -> Result<Vec<FileAcl>> {
    collect_file_acls(client, SENSITIVE_FILE_PATHS).await
}

/// Check if a path has weak permissions (writable by non-admin users)
pub async fn check_weak_permissions(client: &WinRmClient, path: &str) -> Result<Option<Vec<String>>> {
    let acl = get_file_acl(client, path).await?;

    match acl {
        Some(a) => {
            let weak_principals: Vec<String> = a.access_rules.iter()
                .filter(|r| {
                    matches!(r.access_type, AccessControlType::Allow) &&
                    (r.file_rights.modify || r.file_rights.write || r.file_rights.full_control) &&
                    is_non_admin_identity(&r.identity)
                })
                .map(|r| format!("{} has {}", r.identity, r.file_rights.raw_value))
                .collect();

            if weak_principals.is_empty() {
                Ok(None)
            } else {
                Ok(Some(weak_principals))
            }
        }
        None => Ok(None),
    }
}

fn is_non_admin_identity(identity: &str) -> bool {
    let identity_lower = identity.to_lowercase();
    identity_lower.contains("users") ||
    identity_lower.contains("everyone") ||
    identity_lower.contains("authenticated users") ||
    identity_lower.contains("guests")
}

/// Find files with Everyone write access
pub async fn find_files_with_everyone_write(client: &WinRmClient, search_path: &str) -> Result<Vec<String>> {
    let script = format!(r#"
$results = @()
$searchPath = '{}'

if (Test-Path $searchPath) {{
    Get-ChildItem $searchPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
        try {{
            $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
            foreach ($rule in $acl.Access) {{
                if ($rule.IdentityReference -eq 'Everyone' -and
                    $rule.AccessControlType -eq 'Allow' -and
                    ($rule.FileSystemRights -match 'Write|Modify|FullControl')) {{
                    $results += $_.FullName
                    break
                }}
            }}
        }} catch {{}}
    }} | Select-Object -First 100
}}

$results | ConvertTo-Json -Compress
"#, search_path.replace("'", "''"));

    let output = client.execute_powershell(&script).await?;
    let trimmed = output.trim();

    if trimmed.is_empty() || trimmed == "null" || trimmed == "[]" {
        return Ok(Vec::new());
    }

    Ok(serde_json::from_str(trimmed).unwrap_or_default())
}

/// Check if file auditing is configured for security-sensitive paths
pub async fn check_file_auditing(client: &WinRmClient, path: &str) -> Result<bool> {
    let acl = get_file_acl(client, path).await?;

    match acl {
        Some(a) => Ok(!a.audit_rules.is_empty()),
        None => Ok(false),
    }
}

/// STIG-related filesystem checks
pub mod stig_checks {
    use super::*;

    /// V-220749: System files must be protected from unauthorized modification
    pub async fn check_system_files_protected(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let system_paths = vec![
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ];

        let mut issues = Vec::new();

        for path in system_paths {
            if let Some(weak) = check_weak_permissions(client, path).await? {
                for w in weak {
                    issues.push(format!("{}: {}", path, w));
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220750: System directory must have proper permissions
    pub async fn check_windows_directory_permissions(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let acl = get_file_acl(client, r"C:\Windows").await?;
        let mut issues = Vec::new();

        if let Some(a) = acl {
            // Check for inappropriate write access
            for rule in &a.access_rules {
                if matches!(rule.access_type, AccessControlType::Allow) &&
                   (rule.file_rights.modify || rule.file_rights.write || rule.file_rights.full_control) {
                    let identity_lower = rule.identity.to_lowercase();
                    if identity_lower.contains("users") && !identity_lower.contains("trusted") {
                        issues.push(format!("{} has write access to C:\\Windows", rule.identity));
                    }
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220751: Security event log must have proper permissions
    pub async fn check_security_log_permissions(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let log_path = r"C:\Windows\System32\winevt\Logs\Security.evtx";
        let acl = get_file_acl(client, log_path).await?;
        let mut issues = Vec::new();

        if let Some(a) = acl {
            // Non-admins should not have modify access
            for rule in &a.access_rules {
                if matches!(rule.access_type, AccessControlType::Allow) &&
                   (rule.file_rights.modify || rule.file_rights.delete || rule.file_rights.full_control) {
                    if is_non_admin_identity(&rule.identity) {
                        issues.push(format!("{} has modify access to security log", rule.identity));
                    }
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220752: SAM database must be protected
    pub async fn check_sam_database_permissions(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let sam_path = r"C:\Windows\System32\config\SAM";
        let acl = get_file_acl(client, sam_path).await?;
        let mut issues = Vec::new();

        if let Some(a) = acl {
            // Only SYSTEM and Administrators should have access
            for rule in &a.access_rules {
                if matches!(rule.access_type, AccessControlType::Allow) {
                    let identity_lower = rule.identity.to_lowercase();
                    if !identity_lower.contains("system") &&
                       !identity_lower.contains("administrators") &&
                       !identity_lower.contains("trustedinstaller") {
                        issues.push(format!("{} has access to SAM database", rule.identity));
                    }
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220753: Hosts file must have proper permissions
    pub async fn check_hosts_file_permissions(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
        let acl = get_file_acl(client, hosts_path).await?;
        let mut issues = Vec::new();

        if let Some(a) = acl {
            for rule in &a.access_rules {
                if matches!(rule.access_type, AccessControlType::Allow) &&
                   (rule.file_rights.modify || rule.file_rights.write || rule.file_rights.full_control) {
                    if is_non_admin_identity(&rule.identity) {
                        issues.push(format!("{} can modify hosts file", rule.identity));
                    }
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// V-220754: Scheduled tasks folder must be protected
    pub async fn check_scheduled_tasks_permissions(client: &WinRmClient) -> Result<(bool, Vec<String>)> {
        let tasks_path = r"C:\Windows\System32\Tasks";
        let acl = get_file_acl(client, tasks_path).await?;
        let mut issues = Vec::new();

        if let Some(a) = acl {
            for rule in &a.access_rules {
                if matches!(rule.access_type, AccessControlType::Allow) &&
                   (rule.file_rights.modify || rule.file_rights.write || rule.file_rights.full_control) {
                    if is_non_admin_identity(&rule.identity) {
                        issues.push(format!("{} can modify scheduled tasks", rule.identity));
                    }
                }
            }
        }

        Ok((issues.is_empty(), issues))
    }

    /// Check all sensitive paths for proper permissions
    pub async fn check_all_sensitive_paths(client: &WinRmClient) -> Result<Vec<(String, bool, String)>> {
        let mut results = Vec::new();

        // Windows directory
        let (win_ok, win_issues) = check_windows_directory_permissions(client).await?;
        results.push(("Windows directory permissions".to_string(), win_ok,
            if win_ok { "Compliant".to_string() } else { win_issues.join("; ") }));

        // SAM database
        let (sam_ok, sam_issues) = check_sam_database_permissions(client).await?;
        results.push(("SAM database permissions".to_string(), sam_ok,
            if sam_ok { "Compliant".to_string() } else { sam_issues.join("; ") }));

        // Hosts file
        let (hosts_ok, hosts_issues) = check_hosts_file_permissions(client).await?;
        results.push(("Hosts file permissions".to_string(), hosts_ok,
            if hosts_ok { "Compliant".to_string() } else { hosts_issues.join("; ") }));

        // Scheduled tasks
        let (tasks_ok, tasks_issues) = check_scheduled_tasks_permissions(client).await?;
        results.push(("Scheduled tasks permissions".to_string(), tasks_ok,
            if tasks_ok { "Compliant".to_string() } else { tasks_issues.join("; ") }));

        // Security log
        let (log_ok, log_issues) = check_security_log_permissions(client).await?;
        results.push(("Security log permissions".to_string(), log_ok,
            if log_ok { "Compliant".to_string() } else { log_issues.join("; ") }));

        Ok(results)
    }
}
