//! VPN Manager - Coordinates VPN connections
//!
//! Provides a high-level interface for managing VPN connections,
//! including connection lifecycle, state tracking, and cleanup.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;

use super::credentials::{decrypt_vpn_credentials, VpnCredentials};
use super::openvpn::OpenVpnConnection;
use super::types::{ConnectionMode, VpnConnectionInfo, VpnStatus, VpnType};
use super::wireguard::{generate_interface_name, WireGuardConnection};

/// Default connection timeout (30 seconds)
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// VPN Manager singleton instance
static VPN_MANAGER: once_cell::sync::Lazy<VpnManager> =
    once_cell::sync::Lazy::new(VpnManager::new);

/// Active VPN connection state
enum ActiveConnection {
    OpenVPN(OpenVpnConnection),
    WireGuard(WireGuardConnection),
}

impl ActiveConnection {
    async fn disconnect(&mut self) -> Result<()> {
        match self {
            ActiveConnection::OpenVPN(conn) => conn.disconnect().await,
            ActiveConnection::WireGuard(conn) => conn.disconnect().await,
        }
    }

    async fn is_alive(&self) -> bool {
        match self {
            ActiveConnection::OpenVPN(conn) => conn.is_alive().await,
            ActiveConnection::WireGuard(conn) => conn.is_alive().await,
        }
    }

    async fn get_pid(&self) -> Option<u32> {
        match self {
            ActiveConnection::OpenVPN(conn) => conn.get_pid().await,
            ActiveConnection::WireGuard(_) => None, // WireGuard doesn't have a daemon PID
        }
    }
}

/// VPN Connection Manager
///
/// Manages VPN connections for all users. Ensures one active VPN connection
/// per user at a time.
pub struct VpnManager {
    /// Active connections by user_id
    connections: Arc<RwLock<HashMap<String, ActiveVpnSession>>>,
    /// VPN config storage directory
    config_dir: PathBuf,
    /// Connection timeout
    connection_timeout: Duration,
}

/// An active VPN session with metadata
struct ActiveVpnSession {
    connection: ActiveConnection,
    info: VpnConnectionInfo,
}

impl VpnManager {
    /// Create a new VPN manager
    pub fn new() -> Self {
        let config_dir = std::env::var("VPN_CONFIGS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/app/vpn_configs"));

        let timeout_secs = std::env::var("VPN_CONNECTION_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            config_dir,
            connection_timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Get the global VPN manager instance
    pub fn global() -> &'static VpnManager {
        &VPN_MANAGER
    }

    /// Connect to VPN using the specified configuration
    ///
    /// # Arguments
    /// * `user_id` - User initiating the connection
    /// * `config_id` - VPN config ID
    /// * `config_name` - Config name (for display)
    /// * `vpn_type` - VPN type (OpenVPN or WireGuard)
    /// * `config_file_path` - Path to the config file
    /// * `encrypted_credentials` - Optional encrypted credentials
    /// * `mode` - Connection mode (PerScan or Persistent)
    /// * `scan_id` - Associated scan ID (for PerScan mode)
    ///
    /// # Returns
    /// * Connection info with assigned IP and status
    pub async fn connect(
        &self,
        user_id: &str,
        config_id: &str,
        config_name: &str,
        vpn_type: VpnType,
        config_file_path: &Path,
        encrypted_credentials: Option<&str>,
        mode: ConnectionMode,
        scan_id: Option<String>,
    ) -> Result<VpnConnectionInfo> {
        // Disconnect any existing connection for this user
        self.disconnect_user(user_id).await?;

        // Decrypt credentials if present
        let credentials = if let Some(encrypted) = encrypted_credentials {
            Some(decrypt_vpn_credentials(encrypted)?)
        } else {
            None
        };

        // Generate unique interface name
        let interface_name = match vpn_type {
            VpnType::OpenVPN => format!("tun_{}", &user_id[..6.min(user_id.len())]),
            VpnType::WireGuard => generate_interface_name(user_id),
        };

        // Create and connect based on VPN type
        let (connection, status) = match vpn_type {
            VpnType::OpenVPN => {
                let mut conn = OpenVpnConnection::new(config_file_path, &interface_name);
                let status = conn
                    .connect(credentials.as_ref(), self.connection_timeout)
                    .await?;
                (ActiveConnection::OpenVPN(conn), status)
            }
            VpnType::WireGuard => {
                let conn = WireGuardConnection::new(config_file_path, &interface_name);
                let status = conn.connect(self.connection_timeout).await?;
                (ActiveConnection::WireGuard(conn), status)
            }
        };

        // Extract connection details
        let (assigned_ip, interface) = match &status {
            VpnStatus::Connected { assigned_ip, interface } => {
                (Some(assigned_ip.clone()), Some(interface.clone()))
            }
            _ => (None, None),
        };

        // Create connection info
        let connection_id = uuid::Uuid::new_v4().to_string();
        let info = VpnConnectionInfo {
            id: connection_id.clone(),
            config_id: config_id.to_string(),
            config_name: config_name.to_string(),
            user_id: user_id.to_string(),
            mode,
            scan_id,
            status: status.clone(),
            process_id: connection.get_pid().await,
            interface_name: interface,
            assigned_ip,
            connected_at: Some(chrono::Utc::now()),
        };

        // Store active session
        let session = ActiveVpnSession {
            connection,
            info: info.clone(),
        };

        self.connections
            .write()
            .await
            .insert(user_id.to_string(), session);

        log::info!(
            "VPN connected for user {} using config {} ({})",
            user_id,
            config_name,
            vpn_type
        );

        Ok(info)
    }

    /// Disconnect VPN for a specific user
    pub async fn disconnect_user(&self, user_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;

        if let Some(mut session) = connections.remove(user_id) {
            log::info!(
                "Disconnecting VPN for user {} (config: {})",
                user_id,
                session.info.config_name
            );

            session.connection.disconnect().await?;
        }

        Ok(())
    }

    /// Disconnect VPN by connection ID
    pub async fn disconnect(&self, connection_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;

        // Find and remove the connection
        let user_id = connections
            .iter()
            .find(|(_, session)| session.info.id == connection_id)
            .map(|(user_id, _)| user_id.clone());

        if let Some(user_id) = user_id {
            if let Some(mut session) = connections.remove(&user_id) {
                session.connection.disconnect().await?;
            }
        }

        Ok(())
    }

    /// Disconnect VPN associated with a scan
    pub async fn disconnect_scan(&self, scan_id: &str) -> Result<()> {
        let mut connections = self.connections.write().await;

        // Find connection associated with this scan
        let user_id = connections
            .iter()
            .find(|(_, session)| {
                session.info.scan_id.as_deref() == Some(scan_id)
                    && session.info.mode == ConnectionMode::PerScan
            })
            .map(|(user_id, _)| user_id.clone());

        if let Some(user_id) = user_id {
            if let Some(mut session) = connections.remove(&user_id) {
                log::info!(
                    "Disconnecting per-scan VPN for scan {} (user: {})",
                    scan_id,
                    user_id
                );
                session.connection.disconnect().await?;
            }
        }

        Ok(())
    }

    /// Get current VPN status for a user
    pub async fn get_user_status(&self, user_id: &str) -> Option<VpnConnectionInfo> {
        let connections = self.connections.read().await;
        connections.get(user_id).map(|s| s.info.clone())
    }

    /// Get current VPN status by connection ID
    pub async fn get_status(&self, connection_id: &str) -> Option<VpnConnectionInfo> {
        let connections = self.connections.read().await;
        connections
            .values()
            .find(|s| s.info.id == connection_id)
            .map(|s| s.info.clone())
    }

    /// Check if a user has an active VPN connection
    pub async fn is_connected(&self, user_id: &str) -> bool {
        let connections = self.connections.read().await;
        if let Some(session) = connections.get(user_id) {
            session.connection.is_alive().await
        } else {
            false
        }
    }

    /// Get all active connections
    pub async fn list_active_connections(&self) -> Vec<VpnConnectionInfo> {
        let connections = self.connections.read().await;
        connections.values().map(|s| s.info.clone()).collect()
    }

    /// Cleanup stale connections
    ///
    /// Removes connections where the process has died unexpectedly.
    pub async fn cleanup_stale_connections(&self) {
        let mut connections = self.connections.write().await;
        let mut stale_users = Vec::new();

        for (user_id, session) in connections.iter() {
            if !session.connection.is_alive().await {
                stale_users.push(user_id.clone());
            }
        }

        for user_id in stale_users {
            log::warn!("Removing stale VPN connection for user {}", user_id);
            if let Some(mut session) = connections.remove(&user_id) {
                let _ = session.connection.disconnect().await;
            }
        }
    }

    /// Disconnect all connections (used during shutdown)
    pub async fn disconnect_all(&self) -> Result<()> {
        let mut connections = self.connections.write().await;

        for (user_id, mut session) in connections.drain() {
            log::info!("Disconnecting VPN for user {} during shutdown", user_id);
            let _ = session.connection.disconnect().await;
        }

        Ok(())
    }

    /// Get the VPN config directory
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Get the config directory for a specific user
    pub fn user_config_dir(&self, user_id: &str) -> PathBuf {
        self.config_dir.join(user_id)
    }

    /// Ensure user config directory exists
    pub async fn ensure_user_config_dir(&self, user_id: &str) -> Result<PathBuf> {
        let dir = self.user_config_dir(user_id);
        tokio::fs::create_dir_all(&dir)
            .await
            .context("Failed to create VPN config directory")?;
        Ok(dir)
    }

    /// Save a VPN config file for a user
    pub async fn save_config_file(
        &self,
        user_id: &str,
        config_id: &str,
        content: &[u8],
        extension: &str,
    ) -> Result<PathBuf> {
        let dir = self.ensure_user_config_dir(user_id).await?;
        let filename = format!("{}.{}", config_id, extension);
        let file_path = dir.join(&filename);

        tokio::fs::write(&file_path, content)
            .await
            .context("Failed to save VPN config file")?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&file_path, perms).await?;
        }

        Ok(file_path)
    }

    /// Delete a VPN config file
    pub async fn delete_config_file(&self, user_id: &str, config_id: &str) -> Result<()> {
        let dir = self.user_config_dir(user_id);

        // Try both extensions
        for ext in &["ovpn", "conf"] {
            let file_path = dir.join(format!("{}.{}", config_id, ext));
            if file_path.exists() {
                tokio::fs::remove_file(&file_path).await?;
            }
        }

        Ok(())
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_manager_creation() {
        let manager = VpnManager::new();
        assert!(manager.list_active_connections().await.is_empty());
    }

    #[test]
    fn test_user_config_dir() {
        let manager = VpnManager::new();
        let dir = manager.user_config_dir("test-user-123");
        assert!(dir.ends_with("test-user-123"));
    }
}
