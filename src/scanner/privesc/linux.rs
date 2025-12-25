#![allow(dead_code)]

use regex::Regex;
use std::collections::HashSet;

use super::gtfobins::{get_gtfobins_url, is_gtfobins_binary};
use super::types::*;

/// Common exploitable SUID binaries to check
const INTERESTING_SUID_BINARIES: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh",
    "python", "python2", "python3", "perl", "ruby", "php",
    "node", "lua", "awk", "gawk", "nawk", "mawk",
    "vim", "vi", "nano", "emacs", "ed", "pico",
    "less", "more", "most", "view",
    "find", "xargs", "env", "time", "timeout", "stdbuf",
    "nmap", "nc", "netcat", "ncat", "socat", "telnet",
    "wget", "curl", "fetch", "ftp", "tftp", "scp",
    "git", "svn", "hg", "cvs",
    "tar", "zip", "unzip", "gzip", "bzip2", "xz", "cpio", "ar",
    "cp", "mv", "dd", "cat", "head", "tail", "tee", "split",
    "sed", "awk", "cut", "sort", "uniq", "tr", "strings",
    "expect", "script", "screen", "tmux", "byobu",
    "gdb", "strace", "ltrace", "ptrace",
    "docker", "lxc", "podman", "runc", "containerd",
    "systemctl", "journalctl", "service", "chkconfig",
    "mount", "umount", "fusermount",
    "ssh", "sshpass", "ssh-keygen", "ssh-agent",
    "sudo", "su", "doas", "pkexec", "runuser",
    "passwd", "chsh", "chfn", "newgrp",
    "exim", "sendmail", "mail", "mailx",
    "mysql", "psql", "sqlite3", "mongo",
    "tcpdump", "wireshark", "tshark", "dumpcap",
    "apache2", "nginx", "httpd", "lighttpd",
    "ld.so", "ld-linux.so",
];

/// Interesting sudo commands to flag
const INTERESTING_SUDO_COMMANDS: &[&str] = &[
    "ALL", "NOPASSWD", "/bin/bash", "/bin/sh",
    "python", "perl", "ruby", "php", "node",
    "vim", "vi", "nano", "less", "more",
    "find", "awk", "sed", "env", "git",
    "tar", "zip", "wget", "curl", "nc",
    "nmap", "tcpdump", "docker", "lxc",
    "mount", "umount", "dd", "cp", "mv",
    "systemctl", "journalctl", "service",
    "apt", "apt-get", "yum", "dnf", "pip",
    "mysql", "psql", "sqlite3",
];

/// Parse SUID binaries from find output
pub fn parse_suid_binaries(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let seen: HashSet<String> = HashSet::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("find:") {
            continue;
        }

        // Parse permissions and path from ls -la output or just path
        let (path, owner, perms) = if line.contains(' ') {
            // Likely ls -la format: -rwsr-xr-x 1 root root 12345 Jan 1 00:00 /usr/bin/passwd
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                (
                    parts[8..].join(" "),
                    parts.get(2).unwrap_or(&"unknown").to_string(),
                    parts.first().unwrap_or(&"").to_string(),
                )
            } else {
                (line.to_string(), "unknown".to_string(), String::new())
            }
        } else {
            (line.to_string(), "unknown".to_string(), String::new())
        };

        if seen.contains(&path) {
            continue;
        }

        // Extract binary name
        let binary_name = path.rsplit('/').next().unwrap_or(&path);

        // Check if it's a known exploitable binary
        let is_exploitable = is_gtfobins_binary(binary_name)
            || INTERESTING_SUID_BINARIES.iter().any(|b| binary_name.contains(b));

        if is_exploitable {
            let gtfobins_url = get_gtfobins_url(binary_name);
            let severity = if gtfobins_url.is_some() {
                PrivescSeverity::High
            } else if INTERESTING_SUID_BINARIES.iter().any(|b| binary_name == *b) {
                PrivescSeverity::Medium
            } else {
                PrivescSeverity::Low
            };

            let mut finding = PrivescFinding::new_linux(
                severity,
                format!("SUID Binary: {}", binary_name),
                format!(
                    "SUID binary '{}' found at '{}'. {}",
                    binary_name,
                    path,
                    if gtfobins_url.is_some() {
                        "This binary is known to be exploitable via GTFOBins."
                    } else {
                        "This binary may allow privilege escalation."
                    }
                ),
                LinuxPrivescVector::SuidBinary {
                    path: path.clone(),
                    owner,
                    permissions: perms,
                    exploitable: gtfobins_url.is_some(),
                    gtfobins_url: gtfobins_url.clone(),
                },
            );

            if let Some(url) = &gtfobins_url {
                finding.references.push(url.clone());
                finding.exploitation_steps = vec![
                    format!("Visit {} for exploitation techniques", url),
                    format!("Execute: {} (check GTFOBins for specific commands)", path),
                ];
            }

            finding.mitre_techniques.push("T1548.001".to_string()); // Setuid and Setgid

            findings.push(finding);
        }
    }

    findings
}

/// Parse sudo -l output
pub fn parse_sudo_rules(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Look for (ALL) or (root) or specific commands
    let rule_regex = Regex::new(r"\(([^)]+)\)\s*(.+)").ok();

    for line in output.lines() {
        let line = line.trim();

        // Skip non-rule lines
        if !line.contains("(") || line.starts_with("User") || line.starts_with("Matching") {
            continue;
        }

        let is_nopasswd = line.contains("NOPASSWD");
        let is_all = line.contains("(ALL)") || line.contains("ALL : ALL");

        // Check for interesting commands
        let has_interesting = INTERESTING_SUDO_COMMANDS.iter().any(|cmd| line.contains(cmd));

        if is_nopasswd || is_all || has_interesting {
            let severity = if is_all && is_nopasswd {
                PrivescSeverity::Critical
            } else if is_all || is_nopasswd {
                PrivescSeverity::High
            } else {
                PrivescSeverity::Medium
            };

            // Try to extract the command for GTFOBins lookup
            let mut gtfobins_url = None;
            if let Some(ref regex) = rule_regex {
                if let Some(caps) = regex.captures(line) {
                    if let Some(command_part) = caps.get(2) {
                        let cmd = command_part.as_str().split_whitespace().next().unwrap_or("");
                        let binary = cmd.rsplit('/').next().unwrap_or(cmd);
                        gtfobins_url = get_gtfobins_url(binary);
                    }
                }
            }

            let mut finding = PrivescFinding::new_linux(
                severity,
                format!(
                    "Sudo Rule: {}",
                    if is_all && is_nopasswd {
                        "ALL NOPASSWD"
                    } else if is_all {
                        "ALL commands"
                    } else if is_nopasswd {
                        "NOPASSWD"
                    } else {
                        "Interesting command"
                    }
                ),
                format!(
                    "Exploitable sudo rule found: '{}'. {}",
                    line,
                    if is_nopasswd {
                        "No password required."
                    } else {
                        "Password required."
                    }
                ),
                LinuxPrivescVector::SudoRule {
                    rule: line.to_string(),
                    exploitable: is_nopasswd || is_all,
                    gtfobins_url: gtfobins_url.clone(),
                },
            );

            if let Some(url) = &gtfobins_url {
                finding.references.push(url.clone());
            }

            if is_all && is_nopasswd {
                finding.exploitation_steps = vec![
                    "Execute: sudo su".to_string(),
                    "Or: sudo /bin/bash".to_string(),
                ];
            }

            finding.mitre_techniques.push("T1548.003".to_string()); // Sudo and Sudo Caching

            findings.push(finding);
        }
    }

    findings
}

/// Parse crontab output
pub fn parse_crontabs(output: &str, writable_paths: &HashSet<String>) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let cron_regex = Regex::new(r"^([*\d,/-]+\s+){5}(.+)$").ok();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(ref regex) = cron_regex {
            if let Some(caps) = regex.captures(line) {
                if let Some(command_match) = caps.get(2) {
                    let command = command_match.as_str();

                    // Extract script/binary path
                    let parts: Vec<&str> = command.split_whitespace().collect();
                    if let Some(script_path) = parts.first() {
                        let is_writable = writable_paths.contains(*script_path)
                            || script_path.starts_with("/tmp")
                            || script_path.starts_with("/var/tmp");

                        let severity = if is_writable {
                            PrivescSeverity::High
                        } else {
                            PrivescSeverity::Low
                        };

                        let schedule = line.split_whitespace().take(5).collect::<Vec<_>>().join(" ");

                        let mut finding = PrivescFinding::new_linux(
                            severity,
                            format!("Cron Job: {}", script_path),
                            format!(
                                "Cron job found running '{}'. {}",
                                command,
                                if is_writable {
                                    "The script path appears to be writable!"
                                } else {
                                    "Check if the script or its directory is writable."
                                }
                            ),
                            LinuxPrivescVector::CronJob {
                                path: script_path.to_string(),
                                schedule,
                                command: command.to_string(),
                                writable: is_writable,
                            },
                        );

                        if is_writable {
                            finding.exploitation_steps = vec![
                                format!("Modify the script at '{}'", script_path),
                                "Add reverse shell or privilege escalation payload".to_string(),
                                "Wait for cron to execute the modified script".to_string(),
                            ];
                        }

                        finding.mitre_techniques.push("T1053.003".to_string()); // Cron

                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Parse capabilities output (getcap -r /)
pub fn parse_capabilities(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let cap_regex = Regex::new(r"^(.+)\s+=\s+(.+)$").ok();

    // Dangerous capabilities
    let dangerous_caps = [
        "cap_setuid",
        "cap_setgid",
        "cap_sys_admin",
        "cap_sys_ptrace",
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_fowner",
        "cap_net_raw",
        "cap_net_admin",
        "cap_sys_module",
        "cap_sys_rawio",
        "cap_chown",
    ];

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Failed") || line.starts_with("Cannot") {
            continue;
        }

        if let Some(ref regex) = cap_regex {
            if let Some(caps) = regex.captures(line) {
                let binary = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let capabilities = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                let cap_list: Vec<String> = capabilities
                    .split(',')
                    .map(|c| c.trim().to_lowercase())
                    .collect();

                let has_dangerous = cap_list
                    .iter()
                    .any(|c| dangerous_caps.iter().any(|dc| c.contains(dc)));

                if has_dangerous {
                    let binary_name = binary.rsplit('/').next().unwrap_or(binary);
                    let is_gtfobins = is_gtfobins_binary(binary_name);

                    let severity = if cap_list.iter().any(|c| c.contains("cap_setuid")) && is_gtfobins
                    {
                        PrivescSeverity::Critical
                    } else if cap_list.iter().any(|c| c.contains("cap_setuid")) {
                        PrivescSeverity::High
                    } else {
                        PrivescSeverity::Medium
                    };

                    let mut finding = PrivescFinding::new_linux(
                        severity,
                        format!("Capability: {} on {}", capabilities, binary_name),
                        format!(
                            "Binary '{}' has dangerous capabilities: {}. {}",
                            binary,
                            capabilities,
                            if cap_list.iter().any(|c| c.contains("cap_setuid")) {
                                "This can be used to escalate privileges!"
                            } else {
                                "This may allow privilege escalation."
                            }
                        ),
                        LinuxPrivescVector::Capability {
                            binary: binary.to_string(),
                            capabilities: cap_list.clone(),
                            exploitable: is_gtfobins,
                        },
                    );

                    if is_gtfobins {
                        if let Some(url) = get_gtfobins_url(binary_name) {
                            finding.references.push(url);
                        }
                    }

                    if cap_list.iter().any(|c| c.contains("cap_setuid")) && binary_name == "python3"
                    {
                        finding.exploitation_steps = vec![
                            format!(
                                "{} -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                                binary
                            ),
                        ];
                    }

                    finding.mitre_techniques.push("T1068".to_string()); // Exploitation for Privilege Escalation

                    findings.push(finding);
                }
            }
        }
    }

    findings
}

/// Check for Docker socket access
pub fn check_docker_socket(output: &str) -> Option<PrivescFinding> {
    // Check if user is in docker group or can access socket
    let socket_accessible = output.contains("/var/run/docker.sock")
        || output.contains("docker.sock")
        || output.contains("docker:");

    if socket_accessible {
        let mut finding = PrivescFinding::new_linux(
            PrivescSeverity::Critical,
            "Docker Socket Access".to_string(),
            "User can access Docker socket. This allows full root access to the host.".to_string(),
            LinuxPrivescVector::DockerSocket {
                socket_path: "/var/run/docker.sock".to_string(),
                user_in_group: output.contains("docker:"),
            },
        );

        finding.exploitation_steps = vec![
            "docker run -v /:/mnt --rm -it alpine chroot /mnt sh".to_string(),
            "# This gives root shell on the host filesystem".to_string(),
        ];
        finding.references.push("https://gtfobins.github.io/gtfobins/docker/".to_string());
        finding.mitre_techniques.push("T1611".to_string()); // Escape to Host

        return Some(finding);
    }

    None
}

/// Parse kernel version for known exploits
pub fn check_kernel_exploits(kernel_version: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    // Known kernel exploits database (simplified)
    let kernel_exploits = [
        (
            "2.6.22",
            "2.6.38",
            "CVE-2010-3904",
            "RDS Protocol Privilege Escalation",
            "High",
        ),
        (
            "2.6.37",
            "3.8.8",
            "CVE-2013-2094",
            "perf_swevent_init Privilege Escalation",
            "High",
        ),
        (
            "3.0.0",
            "3.19.0",
            "CVE-2015-1328",
            "overlayfs Privilege Escalation",
            "High",
        ),
        (
            "4.4.0",
            "4.13.0",
            "CVE-2017-16995",
            "eBPF Privilege Escalation",
            "High",
        ),
        (
            "4.8.0",
            "4.14.8",
            "CVE-2017-1000112",
            "UFO UDP Fragmentation Offset Privilege Escalation",
            "High",
        ),
        (
            "2.6.0",
            "5.8.0",
            "CVE-2021-3156",
            "Sudo Baron Samedit",
            "Critical",
        ),
        (
            "5.8.0",
            "5.16.0",
            "CVE-2022-0847",
            "Dirty Pipe",
            "Critical",
        ),
        (
            "4.9.0",
            "4.18.0",
            "CVE-2019-13272",
            "PTRACE_TRACEME Privilege Escalation",
            "High",
        ),
    ];

    // Parse version
    let version_regex = Regex::new(r"(\d+)\.(\d+)\.(\d+)").ok();
    if let Some(ref regex) = version_regex {
        if let Some(caps) = regex.captures(kernel_version) {
            let major: u32 = caps.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            let minor: u32 = caps.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            let patch: u32 = caps.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            let version_num = major * 10000 + minor * 100 + patch;

            for (min_ver, max_ver, cve, name, severity_str) in &kernel_exploits {
                let parse_version = |v: &str| -> u32 {
                    let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
                    parts.first().unwrap_or(&0) * 10000
                        + parts.get(1).unwrap_or(&0) * 100
                        + parts.get(2).unwrap_or(&0)
                };

                let min_num = parse_version(min_ver);
                let max_num = parse_version(max_ver);

                if version_num >= min_num && version_num <= max_num {
                    let severity = match *severity_str {
                        "Critical" => PrivescSeverity::Critical,
                        "High" => PrivescSeverity::High,
                        _ => PrivescSeverity::Medium,
                    };

                    let mut finding = PrivescFinding::new_linux(
                        severity,
                        format!("Kernel Exploit: {} ({})", name, cve),
                        format!(
                            "Kernel version {} may be vulnerable to {}. \
                             Affected versions: {} - {}",
                            kernel_version, name, min_ver, max_ver
                        ),
                        LinuxPrivescVector::KernelExploit {
                            kernel_version: kernel_version.to_string(),
                            cve: cve.to_string(),
                            exploit_name: name.to_string(),
                            probability: if version_num >= min_num && version_num <= max_num {
                                "high".to_string()
                            } else {
                                "medium".to_string()
                            },
                        },
                    );

                    finding.references.push(format!("https://nvd.nist.gov/vuln/detail/{}", cve));
                    finding.references.push(format!(
                        "https://www.exploit-db.com/search?cve={}",
                        cve.replace("CVE-", "")
                    ));
                    finding.mitre_techniques.push("T1068".to_string());

                    findings.push(finding);
                }
            }
        }
    }

    findings
}

/// Check for writable /etc/passwd
pub fn check_writable_passwd(output: &str) -> Option<PrivescFinding> {
    if output.contains("-rw-rw") || output.contains("-rwxrwx") || output.contains("world-writable") {
        let mut finding = PrivescFinding::new_linux(
            PrivescSeverity::Critical,
            "Writable /etc/passwd".to_string(),
            "/etc/passwd is writable! This allows adding a new root user.".to_string(),
            LinuxPrivescVector::WritablePasswd {
                file: "/etc/passwd".to_string(),
                writable: true,
            },
        );

        finding.exploitation_steps = vec![
            "Generate password hash: openssl passwd -1 -salt xyz password123".to_string(),
            "Add user: echo 'newroot:$1$xyz$...:0:0:root:/root:/bin/bash' >> /etc/passwd".to_string(),
            "Switch user: su newroot".to_string(),
        ];
        finding.mitre_techniques.push("T1136.001".to_string()); // Create Account: Local Account

        return Some(finding);
    }

    None
}

/// Check for NFS no_root_squash
pub fn check_nfs_no_root_squash(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        if line.contains("no_root_squash") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let export = parts.first().unwrap_or(&"unknown");

            let mut finding = PrivescFinding::new_linux(
                PrivescSeverity::High,
                format!("NFS no_root_squash: {}", export),
                format!(
                    "NFS export '{}' has no_root_squash enabled. \
                     This allows mounting as root and creating SUID binaries.",
                    export
                ),
                LinuxPrivescVector::NfsNoRootSquash {
                    export: export.to_string(),
                    options: line.to_string(),
                },
            );

            finding.exploitation_steps = vec![
                format!("On attacker machine: mount -o rw,vers=3 TARGET_IP:{} /mnt", export),
                "Create SUID shell: cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash".to_string(),
                "On target: /mnt/rootbash -p".to_string(),
            ];
            finding.mitre_techniques.push("T1021.002".to_string()); // Remote Services: SMB/Windows Admin Shares

            findings.push(finding);
        }
    }

    findings
}

/// Parse interesting files found by LinPEAS
pub fn parse_interesting_files(output: &str) -> Vec<PrivescFinding> {
    let mut findings = Vec::new();
    let interesting_patterns = [
        ("password", "Possible password"),
        ("credential", "Possible credentials"),
        ("secret", "Possible secret"),
        ("api_key", "Possible API key"),
        ("apikey", "Possible API key"),
        ("private_key", "Possible private key"),
        ("id_rsa", "SSH private key"),
        ("id_dsa", "SSH private key"),
        ("id_ecdsa", "SSH private key"),
        ("id_ed25519", "SSH private key"),
        (".pem", "Certificate/key file"),
        (".key", "Key file"),
        ("shadow", "Shadow file"),
        ("htpasswd", "HTTP authentication file"),
        ("wp-config.php", "WordPress config"),
        ("config.php", "PHP config"),
        (".env", "Environment file"),
        ("database.yml", "Database config"),
        ("settings.py", "Django settings"),
    ];

    for line in output.lines() {
        let line_lower = line.to_lowercase();
        for (pattern, description) in &interesting_patterns {
            if line_lower.contains(pattern) && !line.starts_with('#') {
                let severity = if pattern.contains("key")
                    || pattern.contains("shadow")
                    || pattern.contains("password")
                {
                    PrivescSeverity::High
                } else {
                    PrivescSeverity::Medium
                };

                let finding = PrivescFinding::new_linux(
                    severity,
                    format!("{}: {}", description, line.trim()),
                    format!("Found interesting file that may contain sensitive data: {}", line),
                    LinuxPrivescVector::InterestingFile {
                        path: line.trim().to_string(),
                        description: description.to_string(),
                    },
                );

                findings.push(finding);
                break; // Only one finding per line
            }
        }
    }

    findings
}

/// Parse system info from various commands
pub fn parse_system_info(
    uname_output: &str,
    hostname_output: &str,
    id_output: &str,
    env_output: &str,
) -> SystemInfo {
    let mut info = SystemInfo::default();

    // Parse hostname
    info.hostname = Some(hostname_output.trim().to_string());

    // Parse uname -a
    let parts: Vec<&str> = uname_output.split_whitespace().collect();
    if parts.len() >= 3 {
        info.os_name = Some(parts[0].to_string());
        info.kernel_version = Some(parts.get(2).unwrap_or(&"").to_string());
        info.architecture = parts.last().map(|s| s.to_string());
    }

    // Parse id output
    if let Some(uid_start) = id_output.find("uid=") {
        if let Some(paren) = id_output[uid_start..].find('(') {
            if let Some(end_paren) = id_output[uid_start + paren..].find(')') {
                info.current_user = Some(
                    id_output[uid_start + paren + 1..uid_start + paren + end_paren].to_string(),
                );
            }
        }
    }

    // Parse groups
    if let Some(groups_start) = id_output.find("groups=") {
        let groups_str = &id_output[groups_start + 7..];
        let group_regex = Regex::new(r"\(([^)]+)\)").ok();
        if let Some(ref regex) = group_regex {
            for cap in regex.captures_iter(groups_str) {
                if let Some(group) = cap.get(1) {
                    info.current_groups.push(group.as_str().to_string());
                }
            }
        }
    }

    // Parse environment variables
    for line in env_output.lines() {
        if let Some(eq_pos) = line.find('=') {
            let key = &line[..eq_pos];
            let value = &line[eq_pos + 1..];
            info.environment_variables
                .insert(key.to_string(), value.to_string());
        }
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_suid_binaries() {
        let output = r#"
/usr/bin/python3
/usr/bin/find
/usr/bin/vim
/usr/bin/passwd
/usr/bin/custom_unknown_binary
"#;
        let findings = parse_suid_binaries(output);
        assert!(findings.iter().any(|f| f.title.contains("python3")));
        assert!(findings.iter().any(|f| f.title.contains("find")));
        assert!(findings.iter().any(|f| f.title.contains("vim")));
    }

    #[test]
    fn test_parse_sudo_rules() {
        let output = r#"
User may run the following commands on target:
    (ALL : ALL) NOPASSWD: ALL
    (root) /usr/bin/find
"#;
        let findings = parse_sudo_rules(output);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == PrivescSeverity::Critical));
    }

    #[test]
    fn test_check_kernel_exploits() {
        let findings = check_kernel_exploits("5.10.0-generic");
        // 5.10.0 is in range for Dirty Pipe
        assert!(findings.iter().any(|f| f.title.contains("Dirty Pipe")));
    }
}
