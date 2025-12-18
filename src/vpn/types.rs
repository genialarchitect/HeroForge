//! VPN type definitions and enums

use serde::{Deserialize, Serialize};

/// Type of VPN protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnType {
    /// OpenVPN protocol (.ovpn files)
    OpenVPN,
    /// WireGuard protocol (.conf files)
    WireGuard,
}

impl VpnType {
    /// Get file extension for this VPN type
    pub fn file_extension(&self) -> &'static str {
        match self {
            VpnType::OpenVPN => "ovpn",
            VpnType::WireGuard => "conf",
        }
    }

    /// Get human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            VpnType::OpenVPN => "OpenVPN",
            VpnType::WireGuard => "WireGuard",
        }
    }

    /// Check if this VPN type requires external credentials (username/password)
    /// OpenVPN can require credentials, WireGuard uses keys in config
    pub fn can_require_credentials(&self) -> bool {
        matches!(self, VpnType::OpenVPN)
    }
}

impl std::fmt::Display for VpnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for VpnType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openvpn" | "ovpn" => Ok(VpnType::OpenVPN),
            "wireguard" | "wg" => Ok(VpnType::WireGuard),
            _ => Err(anyhow::anyhow!("Unknown VPN type: {}", s)),
        }
    }
}

/// VPN connection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    /// Connect VPN for duration of a single scan, then disconnect
    PerScan,
    /// VPN stays connected until explicitly disconnected
    Persistent,
}

impl std::fmt::Display for ConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionMode::PerScan => write!(f, "per_scan"),
            ConnectionMode::Persistent => write!(f, "persistent"),
        }
    }
}

impl std::str::FromStr for ConnectionMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "per_scan" | "perscan" => Ok(ConnectionMode::PerScan),
            "persistent" => Ok(ConnectionMode::Persistent),
            _ => Err(anyhow::anyhow!("Unknown connection mode: {}", s)),
        }
    }
}

/// Current status of a VPN connection
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VpnStatus {
    /// No active connection
    Disconnected,
    /// Connection is being established
    Connecting,
    /// Connection is active
    Connected {
        /// IP address assigned by the VPN
        assigned_ip: String,
        /// Network interface name (e.g., tun0, wg0)
        interface: String,
    },
    /// Connection is being terminated
    Disconnecting,
    /// An error occurred
    Error {
        /// Error message
        message: String,
    },
}

impl VpnStatus {
    /// Check if status indicates an active or pending connection
    pub fn is_active(&self) -> bool {
        matches!(self, VpnStatus::Connected { .. } | VpnStatus::Connecting)
    }

    /// Get status as a simple string for database storage
    pub fn as_db_status(&self) -> &'static str {
        match self {
            VpnStatus::Disconnected => "disconnected",
            VpnStatus::Connecting => "connecting",
            VpnStatus::Connected { .. } => "connected",
            VpnStatus::Disconnecting => "disconnecting",
            VpnStatus::Error { .. } => "error",
        }
    }
}

/// Information about an active VPN connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConnectionInfo {
    /// Unique connection ID
    pub id: String,
    /// VPN config ID being used
    pub config_id: String,
    /// VPN config name (for display)
    pub config_name: String,
    /// User who owns this connection
    pub user_id: String,
    /// Connection mode
    pub mode: ConnectionMode,
    /// Associated scan ID (if per-scan mode)
    pub scan_id: Option<String>,
    /// Current status
    pub status: VpnStatus,
    /// OS process ID of the VPN daemon
    pub process_id: Option<u32>,
    /// Network interface name
    pub interface_name: Option<String>,
    /// Assigned IP address
    pub assigned_ip: Option<String>,
    /// When connection was established
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Database model for VPN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfigRecord {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub vpn_type: String,
    pub config_file_path: String,
    pub original_filename: String,
    pub encrypted_credentials: Option<String>,
    pub requires_credentials: bool,
    pub is_default: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

/// Database model for VPN connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConnectionRecord {
    pub id: String,
    pub vpn_config_id: String,
    pub user_id: String,
    pub connection_mode: String,
    pub scan_id: Option<String>,
    pub status: String,
    pub process_id: Option<i64>,
    pub interface_name: Option<String>,
    pub assigned_ip: Option<String>,
    pub connected_at: Option<String>,
    pub disconnected_at: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
}

/// API response for VPN config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfigResponse {
    pub id: String,
    pub name: String,
    pub vpn_type: String,
    pub requires_credentials: bool,
    pub has_credentials: bool,
    pub is_default: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// API response for VPN status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusResponse {
    pub connected: bool,
    pub config_id: Option<String>,
    pub config_name: Option<String>,
    pub connection_mode: Option<String>,
    pub assigned_ip: Option<String>,
    pub connected_since: Option<String>,
    pub interface_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_type_parsing() {
        assert_eq!("openvpn".parse::<VpnType>().unwrap(), VpnType::OpenVPN);
        assert_eq!("OpenVPN".parse::<VpnType>().unwrap(), VpnType::OpenVPN);
        assert_eq!("wireguard".parse::<VpnType>().unwrap(), VpnType::WireGuard);
        assert_eq!("wg".parse::<VpnType>().unwrap(), VpnType::WireGuard);
    }

    #[test]
    fn test_connection_mode_parsing() {
        assert_eq!("per_scan".parse::<ConnectionMode>().unwrap(), ConnectionMode::PerScan);
        assert_eq!("persistent".parse::<ConnectionMode>().unwrap(), ConnectionMode::Persistent);
    }

    #[test]
    fn test_vpn_status_is_active() {
        assert!(!VpnStatus::Disconnected.is_active());
        assert!(VpnStatus::Connecting.is_active());
        assert!(VpnStatus::Connected {
            assigned_ip: "10.0.0.1".to_string(),
            interface: "tun0".to_string()
        }.is_active());
        assert!(!VpnStatus::Disconnecting.is_active());
        assert!(!VpnStatus::Error { message: "test".to_string() }.is_active());
    }
}
