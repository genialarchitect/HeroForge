use regex::Regex;
use std::collections::HashSet;

use super::windows::*;
use super::types::*;

/// URL to download WinPEAS
pub const WINPEAS_URL: &str = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe";
pub const WINPEAS_X86_URL: &str = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe";

/// Parse WinPEAS output into structured findings
pub fn parse_winpeas_output(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Strip ANSI color codes
    let clean_output = strip_ansi_codes(output);

    // Section markers in WinPEAS output
    // Type annotation required for heterogeneous function items
    type SectionParser = fn(&str) -> Vec<PrivescFinding>;
    let sections: [(&str, SectionParser); 12] = [
        ("═══════════════════════════════════════╣ Services Information", parse_services_section),
        ("═══════════════════════════════════════╣ Interesting Services", parse_services_section),
        ("═══════════════════════════════════════╣ Modifiable Services", parse_modifiable_services_section),
        ("═══════════════════════════════════════╣ Token Information", parse_token_section),
        ("═══════════════════════════════════════╣ Scheduled Tasks", parse_tasks_section),
        ("═══════════════════════════════════════╣ Network Information", parse_network_section),
        ("═══════════════════════════════════════╣ Unattend Files", parse_unattend_section),
        ("═══════════════════════════════════════╣ Credentials", parse_credentials_section),
        ("═══════════════════════════════════════╣ Searching", parse_search_section),
        ("═══════════════════════════════════════╣ AlwaysInstallElevated", parse_aie_section),
        ("═══════════════════════════════════════╣ UAC", parse_uac_section),
        ("═══════════════════════════════════════╣ Registered", parse_autologon_section),
    ];

    // Extract and parse each section
    for (marker, parser) in &sections {
        if let Some(section) = extract_section(&clean_output, marker) {
            findings.extend(parser(&section));
        }
    }

    // Parse CVE mentions
    findings.extend(parse_cve_mentions(&clean_output));

    // Deduplicate findings
    deduplicate_findings(&mut findings);

    findings
}

/// Strip ANSI escape codes from output
fn strip_ansi_codes(input: &str) -> String {
    let ansi_regex = Regex::new(r"\x1B\[[0-9;]*[a-zA-Z]").unwrap();
    ansi_regex.replace_all(input, "").to_string()
}

/// Extract a section from WinPEAS output
fn extract_section(output: &str, start_marker: &str) -> Option<String> {
    let start = output.find(start_marker)?;
    let rest = &output[start..];

    // Find the next section
    let end = rest[1..]
        .find("═══════════════════════════════════════╣")
        .map(|i| i + 1)
        .unwrap_or(rest.len());

    Some(rest[..end].to_string())
}

/// Parse services section for unquoted paths and weak permissions
fn parse_services_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for unquoted service paths
    findings.extend(parse_unquoted_service_paths(section));

    // Look for services running as high-privilege accounts
    for line in section.lines() {
        let line = line.trim();
        if line.contains("LocalSystem") || line.contains("NT AUTHORITY\\SYSTEM") {
            // Services running as SYSTEM are interesting
            if line.contains("SERVICE_NAME:") || line.contains("Name:") {
                let service_name = line
                    .split(':')
                    .nth(1)
                    .map(|s| s.trim())
                    .unwrap_or("Unknown");

                // Only flag if there's something exploitable
                if section.contains("Unquoted") || section.contains("writable") {
                    let finding = PrivescFinding::new_windows(
                        PrivescSeverity::Medium,
                        format!("High-Privilege Service: {}", service_name),
                        format!(
                            "Service '{}' runs as SYSTEM. Check for vulnerabilities.",
                            service_name
                        ),
                        WindowsPrivescVector::WeakServicePermission {
                            service: service_name.to_string(),
                            permission: "SYSTEM".to_string(),
                            identity: "NT AUTHORITY\\SYSTEM".to_string(),
                        },
                    );
                    findings.push(finding);
                }
            }
        }
    }

    findings
}

/// Parse modifiable services section
fn parse_modifiable_services_section(section: &str) -> Vec<PrivescFinding> {
    parse_weak_service_permissions(section)
}

/// Parse token privileges section
fn parse_token_section(section: &str) -> Vec<PrivescFinding> {
    parse_token_privileges(section)
}

/// Parse scheduled tasks section
fn parse_tasks_section(section: &str) -> Vec<PrivescFinding> {
    parse_scheduled_tasks(section)
}

/// Parse network information for interesting ports/services
fn parse_network_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for interesting listening services
    let interesting_ports = [
        (445, "SMB - potential relay attacks"),
        (1433, "MSSQL - check for weak auth"),
        (3306, "MySQL - check for weak auth"),
        (5985, "WinRM - lateral movement"),
        (5986, "WinRM HTTPS - lateral movement"),
    ];

    for line in section.lines() {
        let line = line.trim();
        for (port, description) in &interesting_ports {
            if line.contains(&format!(":{}", port)) || line.contains(&format!(" {} ", port)) {
                let finding = PrivescFinding::new_windows(
                    PrivescSeverity::Info,
                    format!("Listening Port: {}", port),
                    format!("Port {} is listening. {}", port, description),
                    WindowsPrivescVector::WeakServicePermission {
                        service: format!("Port {}", port),
                        permission: "LISTEN".to_string(),
                        identity: "SYSTEM".to_string(),
                    },
                );
                findings.push(finding);
                break;
            }
        }
    }

    findings
}

/// Parse unattend files section
fn parse_unattend_section(section: &str) -> Vec<PrivescFinding> {
    parse_unattended_files(section)
}

/// Parse credentials section
fn parse_credentials_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Parse saved credentials
    findings.extend(parse_saved_credentials(section));

    // Parse registry credentials
    findings.extend(parse_registry_credentials(section));

    // Look for plaintext passwords
    let password_patterns = [
        (r"(?i)password\s*[=:]\s*\S+", "Password found"),
        (r"(?i)DefaultPassword\s*REG_SZ\s*\S+", "Default password in registry"),
        (r"(?i)AutoAdminLogon", "Auto admin logon enabled"),
    ];

    for line in section.lines() {
        let line = line.trim();
        for (pattern, description) in &password_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(line) {
                    let finding = PrivescFinding::new_windows(
                        PrivescSeverity::High,
                        description.to_string(),
                        format!("Potential credential found: {}", line),
                        WindowsPrivescVector::RegistryCredential {
                            path: line.to_string(),
                            value_name: "Password".to_string(),
                        },
                    );
                    findings.push(finding);
                    break;
                }
            }
        }
    }

    findings
}

/// Parse search results for interesting files
fn parse_search_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    let interesting_files = [
        ("web.config", "Web config - may contain connection strings"),
        ("appsettings.json", "App settings - may contain credentials"),
        (".config", "Config file - check for sensitive data"),
        (".xml", "XML file - check for credentials"),
        ("password", "File containing 'password'"),
        ("credential", "File containing 'credential'"),
    ];

    for line in section.lines() {
        let line = line.trim();
        let line_lower = line.to_lowercase();

        for (pattern, description) in &interesting_files {
            if line_lower.contains(pattern) {
                let finding = PrivescFinding::new_windows(
                    PrivescSeverity::Medium,
                    format!("Interesting File: {}", pattern),
                    format!("{}: {}", description, line),
                    WindowsPrivescVector::UnattendedInstall {
                        path: line.to_string(),
                        contains_credentials: false,
                    },
                );
                findings.push(finding);
                break;
            }
        }
    }

    findings
}

/// Parse AlwaysInstallElevated section
fn parse_aie_section(section: &str) -> Vec<PrivescFinding> {
    if let Some(finding) = parse_always_install_elevated(section) {
        vec![finding]
    } else {
        Vec::new()
    }
}

/// Parse UAC section
fn parse_uac_section(section: &str) -> Vec<PrivescFinding> {
    check_uac_bypass_potential(section)
}

/// Parse autologon section
fn parse_autologon_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    if section.contains("DefaultUserName") && section.contains("DefaultPassword") {
        // Extract credentials if visible
        let username_regex = Regex::new(r"DefaultUserName\s+REG_SZ\s+(\S+)").ok();
        let password_regex = Regex::new(r"DefaultPassword\s+REG_SZ\s+(\S+)").ok();

        let username = username_regex
            .as_ref()
            .and_then(|r| r.captures(section))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("Unknown");

        let has_password = password_regex
            .as_ref()
            .map(|r| r.is_match(section))
            .unwrap_or(false);

        if has_password {
            let mut finding = PrivescFinding::new_windows(
                PrivescSeverity::Critical,
                "AutoLogon Credentials Found".to_string(),
                format!(
                    "AutoLogon is configured for user '{}' with password stored in registry.",
                    username
                ),
                WindowsPrivescVector::RegistryCredential {
                    path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                        .to_string(),
                    value_name: "DefaultPassword".to_string(),
                },
            );

            finding.exploitation_steps = vec![
                "Query registry: reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul | findstr /i DefaultPassword".to_string(),
                format!("Use credentials: runas /user:{} cmd", username),
            ];

            finding.mitre_techniques.push("T1552.002".to_string());

            findings.push(finding);
        }
    }

    findings
}

/// Parse CVE mentions in output
fn parse_cve_mentions(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let cve_regex = Regex::new(r"CVE-\d{4}-\d+").ok();
    let mut seen_cves: HashSet<String> = HashSet::new();

    // High-priority Windows CVEs
    let known_critical = [
        ("CVE-2021-1675", "PrintNightmare (LPE)", PrivescSeverity::Critical),
        ("CVE-2021-34527", "PrintNightmare (RCE)", PrivescSeverity::Critical),
        ("CVE-2020-1472", "Zerologon", PrivescSeverity::Critical),
        ("CVE-2019-1388", "UAC Bypass via Certificate Dialog", PrivescSeverity::High),
        ("CVE-2020-0796", "SMBGhost", PrivescSeverity::Critical),
        ("CVE-2017-0143", "EternalBlue", PrivescSeverity::Critical),
    ];

    if let Some(ref regex) = cve_regex {
        for caps in regex.captures_iter(output) {
            if let Some(cve) = caps.get(0) {
                let cve_str = cve.as_str();
                if !seen_cves.contains(cve_str) {
                    seen_cves.insert(cve_str.to_string());

                    // Check if it's a known critical CVE
                    if let Some((_, name, severity)) = known_critical
                        .iter()
                        .find(|(c, _, _)| *c == cve_str)
                    {
                        let mut finding = PrivescFinding::new_windows(
                            *severity,
                            format!("{} ({})", name, cve_str),
                            format!(
                                "WinPEAS detected potential vulnerability: {} - {}",
                                cve_str, name
                            ),
                            WindowsPrivescVector::UacBypass {
                                technique: name.to_string(),
                                binary: "N/A".to_string(),
                            },
                        );

                        finding.references.push(format!(
                            "https://nvd.nist.gov/vuln/detail/{}",
                            cve_str
                        ));
                        finding.mitre_techniques.push("T1068".to_string());

                        findings.push(finding);
                    } else {
                        // Generic CVE finding
                        let finding = PrivescFinding::new_windows(
                            PrivescSeverity::Medium,
                            format!("CVE Detected: {}", cve_str),
                            format!("WinPEAS detected potential vulnerability: {}", cve_str),
                            WindowsPrivescVector::UacBypass {
                                technique: cve_str.to_string(),
                                binary: "N/A".to_string(),
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

/// Remove duplicate findings
fn deduplicate_findings(findings: &mut Vec<PrivescFinding>) {
    let mut seen: HashSet<String> = HashSet::new();
    findings.retain(|f| {
        let key = format!("{}:{}", f.title, f.description);
        if seen.contains(&key) {
            false
        } else {
            seen.insert(key);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_codes() {
        let input = "\x1B[1;31mRed text\x1B[0m";
        let output = strip_ansi_codes(input);
        assert_eq!(output, "Red text");
    }

    #[test]
    fn test_parse_cve_mentions() {
        let output = "System may be vulnerable to CVE-2021-1675 (PrintNightmare)";
        let findings = parse_cve_mentions(output);
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("PrintNightmare"));
    }
}
