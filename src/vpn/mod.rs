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

pub use types::{VpnType, ConnectionMode};
pub use manager::VpnManager;
