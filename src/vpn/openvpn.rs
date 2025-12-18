//! OpenVPN connection management
//!
//! Spawns and manages OpenVPN daemon processes for VPN connections.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use super::credentials::VpnCredentials;
use super::types::VpnStatus;

/// OpenVPN connection manager
pub struct OpenVpnConnection {
    config_path: PathBuf,
    credentials_path: Option<PathBuf>,
    process: Arc<Mutex<Option<Child>>>,
    interface_name: String,
}

impl OpenVpnConnection {
    /// Create a new OpenVPN connection instance
    pub fn new(config_path: impl AsRef<Path>, interface_name: impl Into<String>) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            credentials_path: None,
            process: Arc::new(Mutex::new(None)),
            interface_name: interface_name.into(),
        }
    }

    /// Establish VPN connection
    ///
    /// # Arguments
    /// * `credentials` - Optional username/password for auth-user-pass
    /// * `connection_timeout` - Maximum time to wait for connection
    ///
    /// # Returns
    /// * VPN status with assigned IP and interface name
    pub async fn connect(
        &mut self,
        credentials: Option<&VpnCredentials>,
        connection_timeout: Duration,
    ) -> Result<VpnStatus> {
        // Clean up any existing connection
        self.disconnect().await?;

        // Write credentials to temp file if provided
        if let Some(creds) = credentials {
            let creds_path = self.write_credentials_file(creds).await?;
            self.credentials_path = Some(creds_path);
        }

        // Build OpenVPN command
        let mut cmd = Command::new("openvpn");
        cmd.arg("--config")
            .arg(&self.config_path)
            .arg("--dev")
            .arg(&self.interface_name)
            .arg("--verb")
            .arg("3")
            .arg("--writepid")
            .arg(format!("/tmp/openvpn_{}.pid", self.interface_name));

        // Add credentials file if present
        if let Some(ref creds_path) = self.credentials_path {
            cmd.arg("--auth-user-pass").arg(creds_path);
        }

        // Prevent OpenVPN from backgrounding
        cmd.arg("--daemon-log")
            .arg(format!("/tmp/openvpn_{}.log", self.interface_name));

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn OpenVPN process
        let mut child = cmd.spawn()
            .context("Failed to spawn OpenVPN process. Is OpenVPN installed?")?;

        // Get stdout for monitoring
        let stdout = child.stdout.take()
            .context("Failed to capture OpenVPN stdout")?;

        let stderr = child.stderr.take();

        // Store process handle
        let pid = child.id();
        *self.process.lock().await = Some(child);

        // Monitor output for connection status
        let result = timeout(connection_timeout, async {
            self.wait_for_connection(stdout, stderr).await
        }).await;

        // Clean up credentials file after connection attempt
        self.cleanup_credentials_file().await;

        match result {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(e)) => {
                self.disconnect().await?;
                Err(e)
            }
            Err(_) => {
                self.disconnect().await?;
                Err(anyhow::anyhow!(
                    "OpenVPN connection timed out after {:?}",
                    connection_timeout
                ))
            }
        }
    }

    /// Wait for connection and parse assigned IP
    async fn wait_for_connection(
        &self,
        stdout: tokio::process::ChildStdout,
        stderr: Option<tokio::process::ChildStderr>,
    ) -> Result<VpnStatus> {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        let mut assigned_ip: Option<String> = None;
        let mut connected = false;
        let mut error_message: Option<String> = None;

        // Also spawn a task to read stderr for errors
        if let Some(stderr) = stderr {
            let stderr_reader = BufReader::new(stderr);
            let mut stderr_lines = stderr_reader.lines();
            tokio::spawn(async move {
                while let Ok(Some(line)) = stderr_lines.next_line().await {
                    log::debug!("OpenVPN stderr: {}", line);
                }
            });
        }

        while let Ok(Some(line)) = lines.next_line().await {
            log::debug!("OpenVPN: {}", line);

            // Check for successful connection
            if line.contains("Initialization Sequence Completed") {
                connected = true;
                // If we already have the IP, we're done
                if assigned_ip.is_some() {
                    break;
                }
            }

            // Parse assigned IP address
            // OpenVPN outputs: "PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,..."
            // Or: "ip addr add dev tun0 local 10.8.0.2 peer 10.8.0.1"
            if line.contains("ifconfig") {
                // Format: "ifconfig tun0 10.8.0.6 netmask 255.255.255.0"
                if let Some(ip) = Self::parse_ifconfig_ip(&line) {
                    assigned_ip = Some(ip);
                }
            } else if line.contains("PUSH_REPLY") || line.contains("route-gateway") {
                // Extract IP from PUSH_REPLY
                if let Some(ip) = Self::parse_push_reply_ip(&line) {
                    assigned_ip = Some(ip);
                }
            } else if line.contains("ip addr add") {
                // Format: "ip addr add dev tun0 local 10.8.0.2 peer 10.8.0.1"
                if let Some(ip) = Self::parse_ip_addr_ip(&line) {
                    assigned_ip = Some(ip);
                }
            }

            // Check for authentication errors
            if line.contains("AUTH_FAILED") {
                error_message = Some("Authentication failed - check credentials".to_string());
                break;
            }

            // Check for other errors
            if line.contains("Connection refused")
                || line.contains("Connection timed out")
                || line.contains("No route to host")
            {
                error_message = Some(format!("Connection error: {}", line));
                break;
            }

            if connected && assigned_ip.is_some() {
                break;
            }
        }

        if let Some(error) = error_message {
            return Err(anyhow::anyhow!(error));
        }

        if connected {
            Ok(VpnStatus::Connected {
                assigned_ip: assigned_ip.unwrap_or_else(|| "unknown".to_string()),
                interface: self.interface_name.clone(),
            })
        } else {
            Err(anyhow::anyhow!("OpenVPN did not complete initialization"))
        }
    }

    /// Parse IP from ifconfig line
    fn parse_ifconfig_ip(line: &str) -> Option<String> {
        // Format: "ifconfig tun0 10.8.0.6 netmask 255.255.255.0"
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "ifconfig" && i + 2 < parts.len() {
                let potential_ip = parts[i + 2];
                if Self::is_valid_ip(potential_ip) {
                    return Some(potential_ip.to_string());
                }
            }
        }
        None
    }

    /// Parse IP from PUSH_REPLY message
    fn parse_push_reply_ip(line: &str) -> Option<String> {
        // Look for ifconfig-local or similar
        if let Some(start) = line.find("ifconfig ") {
            let rest = &line[start + 9..];
            let ip = rest.split_whitespace().next()?;
            if Self::is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
        None
    }

    /// Parse IP from ip addr add command
    fn parse_ip_addr_ip(line: &str) -> Option<String> {
        // Format: "ip addr add dev tun0 local 10.8.0.2 peer 10.8.0.1"
        if let Some(start) = line.find("local ") {
            let rest = &line[start + 6..];
            let ip = rest.split_whitespace().next()?;
            // Handle CIDR notation
            let ip = ip.split('/').next()?;
            if Self::is_valid_ip(ip) {
                return Some(ip.to_string());
            }
        }
        None
    }

    /// Check if string is a valid IP address
    fn is_valid_ip(s: &str) -> bool {
        s.parse::<std::net::Ipv4Addr>().is_ok()
            || s.parse::<std::net::Ipv6Addr>().is_ok()
    }

    /// Disconnect and cleanup
    pub async fn disconnect(&mut self) -> Result<()> {
        // Scope the mutex guard so it's dropped before cleanup_credentials_file
        {
            let mut process = self.process.lock().await;

            if let Some(mut child) = process.take() {
                // Try graceful shutdown first
                #[cfg(unix)]
                {
                    if let Some(pid) = child.id() {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                    }
                }

                // Wait for graceful shutdown
                let graceful = timeout(Duration::from_secs(5), child.wait()).await;

                if graceful.is_err() {
                    // Force kill if graceful shutdown failed
                    let _ = child.kill().await;
                }
            }
        }

        // Cleanup temp files (mutex guard is now dropped)
        self.cleanup_credentials_file().await;

        // Remove PID file and log file
        let pid_file = format!("/tmp/openvpn_{}.pid", self.interface_name);
        let log_file = format!("/tmp/openvpn_{}.log", self.interface_name);
        let _ = tokio::fs::remove_file(&pid_file).await;
        let _ = tokio::fs::remove_file(&log_file).await;

        Ok(())
    }

    /// Write credentials to temporary file with restricted permissions
    async fn write_credentials_file(&self, creds: &VpnCredentials) -> Result<PathBuf> {
        let creds_path = PathBuf::from(format!(
            "/tmp/openvpn_creds_{}.txt",
            self.interface_name
        ));

        // Format: username on first line, password on second
        let content = format!("{}\n{}\n", creds.username, creds.password);

        // Write file with restricted permissions
        tokio::fs::write(&creds_path, &content).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&creds_path, perms).await?;
        }

        Ok(creds_path)
    }

    /// Clean up credentials file
    async fn cleanup_credentials_file(&mut self) {
        if let Some(ref creds_path) = self.credentials_path {
            // Overwrite with zeros before deleting
            let zeros = vec![0u8; 256];
            let _ = tokio::fs::write(creds_path, &zeros).await;
            let _ = tokio::fs::remove_file(creds_path).await;
            self.credentials_path = None;
        }
    }

    /// Get the process ID of the running OpenVPN daemon
    pub async fn get_pid(&self) -> Option<u32> {
        self.process.lock().await.as_ref()?.id()
    }

    /// Check if the connection is still alive
    pub async fn is_alive(&self) -> bool {
        let mut process = self.process.lock().await;
        if let Some(ref mut child) = *process {
            // Check if process has exited
            match child.try_wait() {
                Ok(None) => true, // Still running
                _ => false,       // Exited or error
            }
        } else {
            false
        }
    }
}

impl Drop for OpenVpnConnection {
    fn drop(&mut self) {
        // Attempt cleanup on drop
        let interface = self.interface_name.clone();
        let pid_file = format!("/tmp/openvpn_{}.pid", interface);
        let log_file = format!("/tmp/openvpn_{}.log", interface);
        let creds_file = format!("/tmp/openvpn_creds_{}.txt", interface);

        // Sync cleanup (best effort)
        let _ = std::fs::remove_file(&pid_file);
        let _ = std::fs::remove_file(&log_file);
        let _ = std::fs::remove_file(&creds_file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ifconfig_ip() {
        let line = "ifconfig tun0 10.8.0.6 netmask 255.255.255.0";
        assert_eq!(OpenVpnConnection::parse_ifconfig_ip(line), Some("10.8.0.6".to_string()));
    }

    #[test]
    fn test_parse_ip_addr_ip() {
        let line = "ip addr add dev tun0 local 10.8.0.2 peer 10.8.0.1";
        assert_eq!(OpenVpnConnection::parse_ip_addr_ip(line), Some("10.8.0.2".to_string()));
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(OpenVpnConnection::is_valid_ip("10.8.0.1"));
        assert!(OpenVpnConnection::is_valid_ip("192.168.1.1"));
        assert!(!OpenVpnConnection::is_valid_ip("not-an-ip"));
        assert!(!OpenVpnConnection::is_valid_ip("256.1.1.1"));
    }
}
