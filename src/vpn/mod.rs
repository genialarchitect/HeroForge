//! VPN connection management module for HeroForge
//!
//! Provides support for OpenVPN and WireGuard VPN connections,
//! allowing scans to be routed through VPN tunnels.

pub mod types;
pub mod credentials;
pub mod config;
pub mod openvpn;
pub mod wireguard;
pub mod manager;

pub use types::{VpnType, ConnectionMode, VpnStatus, VpnConnectionInfo};
pub use credentials::{VpnCredentials, encrypt_vpn_credentials, decrypt_vpn_credentials};
pub use config::{VpnConfigValidator, ConfigValidationResult};
pub use manager::VpnManager;
