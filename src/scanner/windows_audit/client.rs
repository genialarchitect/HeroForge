//! WinRM Client for Windows Remote Management
//!
//! Executes PowerShell commands on remote Windows systems.

use anyhow::{Result, bail, Context};
use tokio::process::Command;
use std::process::Stdio;

use super::types::WindowsCredentials;

/// Escape special characters in a PowerShell string literal
///
/// This handles characters that have special meaning in PowerShell:
/// - Single quotes (') - doubled to escape within single-quoted strings
/// - Backtick (`) - PowerShell escape character
/// - Dollar sign ($) - Variable expansion
/// - Null bytes - Removed as they can break string handling
fn escape_powershell_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\'' => result.push_str("''"),  // Double single quotes
            '`' => result.push_str("``"),   // Escape backtick
            '$' => result.push_str("`$"),   // Escape dollar sign
            '\0' => {},                      // Remove null bytes
            '\n' => result.push_str("`n"),  // Escape newline
            '\r' => result.push_str("`r"),  // Escape carriage return
            '\t' => result.push_str("`t"),  // Escape tab
            _ => result.push(c),
        }
    }
    result
}

/// WinRM client for remote Windows management
pub struct WinRmClient {
    target: String,
    credentials: WindowsCredentials,
    use_ssl: bool,
    port: u16,
}

impl WinRmClient {
    /// Create a new WinRM client
    pub fn new(target: &str, credentials: WindowsCredentials) -> Self {
        Self {
            target: target.to_string(),
            credentials,
            use_ssl: true,
            port: 5986,
        }
    }

    /// Create client with custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Disable SSL (use HTTP instead of HTTPS)
    pub fn without_ssl(mut self) -> Self {
        self.use_ssl = false;
        self.port = 5985;
        self
    }

    /// Execute a PowerShell command on the remote system
    pub async fn execute_powershell(&self, script: &str) -> Result<String> {
        // Try pwsh first, fall back to other methods
        if let Ok(output) = self.execute_via_pwsh(script).await {
            return Ok(output);
        }

        // Try evil-winrm if available
        if let Ok(output) = self.execute_via_evil_winrm(script).await {
            return Ok(output);
        }

        // Try pywinrm if available
        self.execute_via_python(script).await
    }

    /// Execute via PowerShell Core (pwsh)
    async fn execute_via_pwsh(&self, script: &str) -> Result<String> {
        let user = if let Some(ref domain) = self.credentials.domain {
            format!("{}\\{}", domain, self.credentials.username)
        } else {
            self.credentials.username.clone()
        };

        let protocol = if self.use_ssl { "https" } else { "http" };
        let uri = format!("{}://{}:{}/wsman", protocol, self.target, self.port);

        // Create PowerShell script that sets up session and executes
        let ps_script = format!(r#"
$secpasswd = ConvertTo-SecureString '{}' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ('{}', $secpasswd)
$session = New-PSSession -ComputerName '{}' -Credential $credential -UseSSL:${}
Invoke-Command -Session $session -ScriptBlock {{ {} }}
Remove-PSSession $session
"#,
            escape_powershell_string(&self.credentials.password),
            user,
            self.target,
            self.use_ssl,
            script.replace("'", "''")
        );

        let output = Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute pwsh")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("PowerShell execution failed: {}", stderr)
        }
    }

    /// Execute via evil-winrm (Ruby-based tool)
    async fn execute_via_evil_winrm(&self, script: &str) -> Result<String> {
        let user = if let Some(ref domain) = self.credentials.domain {
            format!("{}\\{}", domain, self.credentials.username)
        } else {
            self.credentials.username.clone()
        };

        let mut args = vec![
            "-i".to_string(), self.target.clone(),
            "-u".to_string(), user,
            "-p".to_string(), self.credentials.password.clone(),
        ];

        if self.use_ssl {
            args.push("-S".to_string());
        }

        args.push("-c".to_string());
        args.push(script.to_string());

        let output = Command::new("evil-winrm")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute evil-winrm")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("evil-winrm execution failed: {}", stderr)
        }
    }

    /// Execute via Python pywinrm
    async fn execute_via_python(&self, script: &str) -> Result<String> {
        let user = if let Some(ref domain) = self.credentials.domain {
            format!("{}\\{}", domain, self.credentials.username)
        } else {
            self.credentials.username.clone()
        };

        let protocol = if self.use_ssl { "https" } else { "http" };

        let python_script = format!(r#"
import winrm
import json
import sys

session = winrm.Session(
    '{}://{}:{}',
    auth=(r'{}', r'{}'),
    transport='ntlm',
    server_cert_validation='ignore'
)

result = session.run_ps(r'''{}''')

if result.status_code == 0:
    print(result.std_out.decode('utf-8'))
else:
    print(result.std_err.decode('utf-8'), file=sys.stderr)
    sys.exit(1)
"#,
            protocol,
            self.target,
            self.port,
            user.replace("\\", "\\\\"),
            self.credentials.password.replace("'", "\\'"),
            script.replace("'''", "\\'''")
        );

        let output = Command::new("python3")
            .args(["-c", &python_script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to execute python winrm script")?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Python WinRM execution failed: {}", stderr)
        }
    }

    /// Test connection to the remote system
    pub async fn test_connection(&self) -> Result<bool> {
        match self.execute_powershell("echo 'Connection test successful'").await {
            Ok(output) => Ok(output.contains("Connection test successful")),
            Err(_) => Ok(false),
        }
    }

    /// Get the remote system hostname
    pub async fn get_hostname(&self) -> Result<String> {
        self.execute_powershell("$env:COMPUTERNAME").await
            .map(|s| s.trim().to_string())
    }

    /// Execute multiple commands and return all outputs
    pub async fn execute_batch(&self, scripts: &[&str]) -> Result<Vec<String>> {
        let combined = scripts.join("; ");
        let output = self.execute_powershell(&combined).await?;
        Ok(output.lines().map(|s| s.to_string()).collect())
    }
}

/// PowerShell command builder
pub struct PowerShellCommand {
    script: String,
}

impl PowerShellCommand {
    pub fn new() -> Self {
        Self {
            script: String::new(),
        }
    }

    /// Add a command to the script
    pub fn add_command(&mut self, cmd: &str) -> &mut Self {
        if !self.script.is_empty() {
            self.script.push_str("; ");
        }
        self.script.push_str(cmd);
        self
    }

    /// Add a command to export to JSON
    pub fn add_json_export(&mut self, cmd: &str) -> &mut Self {
        if !self.script.is_empty() {
            self.script.push_str("; ");
        }
        self.script.push_str(cmd);
        self.script.push_str(" | ConvertTo-Json -Depth 5");
        self
    }

    /// Get the final script
    pub fn build(&self) -> &str {
        &self.script
    }
}

impl Default for PowerShellCommand {
    fn default() -> Self {
        Self::new()
    }
}
