//! WireGuard connection management
//!
//! Uses wg-quick for WireGuard VPN connections.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use super::types::VpnStatus;

/// WireGuard connection manager
pub struct WireGuardConnection {
    config_path: PathBuf,
    interface_name: String,
}

impl WireGuardConnection {
    /// Create a new WireGuard connection instance
    ///
    /// # Arguments
    /// * `config_path` - Path to WireGuard .conf file
    /// * `interface_name` - Interface name to use (e.g., wg0)
    pub fn new(config_path: impl AsRef<Path>, interface_name: impl Into<String>) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            interface_name: interface_name.into(),
        }
    }

    /// Establish VPN connection using wg-quick
    ///
    /// # Arguments
    /// * `connection_timeout` - Maximum time to wait for connection
    ///
    /// # Returns
    /// * VPN status with assigned IP and interface name
    pub async fn connect(&self, connection_timeout: Duration) -> Result<VpnStatus> {
        // First, ensure the interface is down (cleanup from any previous state)
        let _ = self.disconnect().await;

        // Create a temporary config file with the interface name
        // WireGuard requires the config name to match the interface name
        let temp_config_path = format!("/etc/wireguard/{}.conf", self.interface_name);

        // Copy config to /etc/wireguard with correct name
        tokio::fs::copy(&self.config_path, &temp_config_path)
            .await
            .context("Failed to copy WireGuard config to /etc/wireguard")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&temp_config_path, perms).await?;
        }

        // Run wg-quick up
        let result = timeout(connection_timeout, async {
            self.run_wg_quick_up().await
        }).await;

        match result {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(e)) => {
                // Clean up on error
                let _ = self.disconnect().await;
                Err(e)
            }
            Err(_) => {
                let _ = self.disconnect().await;
                Err(anyhow::anyhow!(
                    "WireGuard connection timed out after {:?}",
                    connection_timeout
                ))
            }
        }
    }

    /// Run wg-quick up command
    async fn run_wg_quick_up(&self) -> Result<VpnStatus> {
        let output = Command::new("wg-quick")
            .arg("up")
            .arg(&self.interface_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("Failed to run wg-quick. Is WireGuard installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("wg-quick up failed: {}", stderr));
        }

        // Verify interface is up and get assigned IP
        let assigned_ip = self.get_interface_ip().await?;

        Ok(VpnStatus::Connected {
            assigned_ip,
            interface: self.interface_name.clone(),
        })
    }

    /// Get the IP address assigned to the WireGuard interface
    async fn get_interface_ip(&self) -> Result<String> {
        // First try: use `wg show` to verify interface exists
        let wg_output = Command::new("wg")
            .arg("show")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !wg_output.status.success() {
            return Err(anyhow::anyhow!(
                "WireGuard interface {} is not active",
                self.interface_name
            ));
        }

        // Get IP from interface using `ip addr show`
        let ip_output = Command::new("ip")
            .arg("addr")
            .arg("show")
            .arg(&self.interface_name)
            .output()
            .await?;

        if !ip_output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to get IP for interface {}",
                self.interface_name
            ));
        }

        let output = String::from_utf8_lossy(&ip_output.stdout);

        // Parse IP from output
        // Format: "    inet 10.0.0.2/32 scope global wg0"
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    // Remove CIDR notation
                    let ip = parts[1].split('/').next().unwrap_or(parts[1]);
                    return Ok(ip.to_string());
                }
            }
        }

        // If we can't find the IP, the interface is still up, just return unknown
        Ok("unknown".to_string())
    }

    /// Disconnect and cleanup WireGuard interface
    pub async fn disconnect(&self) -> Result<()> {
        // Run wg-quick down
        let output = Command::new("wg-quick")
            .arg("down")
            .arg(&self.interface_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match output {
            Ok(result) => {
                if !result.status.success() {
                    // Interface might not exist, which is fine
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    log::debug!("wg-quick down output: {}", stderr);
                }
            }
            Err(e) => {
                log::debug!("wg-quick down failed: {}", e);
            }
        }

        // Remove the temporary config file
        let temp_config_path = format!("/etc/wireguard/{}.conf", self.interface_name);
        let _ = tokio::fs::remove_file(&temp_config_path).await;

        Ok(())
    }

}

impl Drop for WireGuardConnection {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        let interface = self.interface_name.clone();

        // Use std::process for sync cleanup
        let _ = std::process::Command::new("wg-quick")
            .arg("down")
            .arg(&interface)
            .output();

        // Remove config file
        let config_path = format!("/etc/wireguard/{}.conf", interface);
        let _ = std::fs::remove_file(&config_path);
    }
}

/// Generate a unique WireGuard interface name for a user
pub fn generate_interface_name(user_id: &str) -> String {
    // Use first 6 chars of user_id to create unique interface
    // Format: wg_XXXXXX where X is alphanumeric from user_id
    let clean_id: String = user_id
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(6)
        .collect();

    format!("wg_{}", clean_id.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_interface_name() {
        let name = generate_interface_name("abc123-def456");
        assert_eq!(name, "wg_abc123");

        let name = generate_interface_name("USER-XYZ");
        assert_eq!(name, "wg_userxy");
    }
}
