//! Wireless Security Types
//!
//! Data structures for WiFi security assessment and penetration testing.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Wireless encryption type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WirelessEncryption {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    WpaEnterprise,
    Wpa2Enterprise,
    Unknown,
}

impl std::fmt::Display for WirelessEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::Wep => write!(f, "WEP"),
            Self::Wpa => write!(f, "WPA"),
            Self::Wpa2 => write!(f, "WPA2"),
            Self::Wpa3 => write!(f, "WPA3"),
            Self::WpaEnterprise => write!(f, "WPA-Enterprise"),
            Self::Wpa2Enterprise => write!(f, "WPA2-Enterprise"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Cipher suite used by the network
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CipherSuite {
    Ccmp,  // AES
    Tkip,
    Wep40,
    Wep104,
    Unknown,
}

/// Authentication type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Psk,       // Pre-shared key
    Eap,       // Enterprise
    Open,
    Sae,       // WPA3
    Unknown,
}

/// Wireless interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessInterface {
    pub name: String,
    pub mac_address: String,
    pub driver: String,
    pub chipset: Option<String>,
    pub monitor_mode_supported: bool,
    pub current_mode: String,  // managed, monitor, etc.
    pub channel: Option<u8>,
    pub frequency: Option<u32>,  // MHz
}

/// Discovered wireless network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessNetwork {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub frequency: u32,  // MHz
    pub signal_strength: i8,  // dBm
    pub encryption: WirelessEncryption,
    pub cipher: Option<CipherSuite>,
    pub auth: Option<AuthType>,
    pub wps_enabled: bool,
    pub wps_locked: bool,
    pub clients: Vec<WirelessClient>,
    pub beacons: u32,
    pub data_packets: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Wireless client (station)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessClient {
    pub mac_address: String,
    pub associated_bssid: Option<String>,
    pub signal_strength: i8,
    pub packets: u32,
    pub probes: Vec<String>,  // Probed SSIDs
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Handshake capture result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeCapture {
    pub id: String,
    pub bssid: String,
    pub ssid: String,
    pub client_mac: String,
    pub capture_file: String,
    pub eapol_messages: u8,  // 1-4 for complete handshake
    pub is_complete: bool,
    pub cracked: bool,
    pub password: Option<String>,
    pub captured_at: DateTime<Utc>,
    pub cracked_at: Option<DateTime<Utc>>,
}

/// PMKID capture result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmkidCapture {
    pub id: String,
    pub bssid: String,
    pub ssid: String,
    pub pmkid: String,
    pub capture_file: String,
    pub cracked: bool,
    pub password: Option<String>,
    pub captured_at: DateTime<Utc>,
}

/// Wireless scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessScanConfig {
    pub interface: String,
    pub channels: Option<Vec<u8>>,  // None = all channels
    pub duration_secs: u32,
    pub hop_interval_ms: u32,
    pub capture_handshakes: bool,
    pub capture_pmkid: bool,
}

impl Default for WirelessScanConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            channels: None,
            duration_secs: 60,
            hop_interval_ms: 250,
            capture_handshakes: true,
            capture_pmkid: true,
        }
    }
}

/// Deauthentication attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthConfig {
    pub interface: String,
    pub bssid: String,
    pub client: Option<String>,  // None = broadcast
    pub count: u32,  // Number of deauth packets
    pub reason_code: u8,
}

/// Handshake capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub interface: String,
    pub bssid: String,
    pub channel: u8,
    pub timeout_secs: u32,
    pub deauth_enabled: bool,
    pub deauth_count: u32,
}

/// WPS attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsConfig {
    pub interface: String,
    pub bssid: String,
    pub pin: Option<String>,  // None = pixie dust
    pub timeout_secs: u32,
}

/// Crack job configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackConfig {
    pub capture_file: String,
    pub wordlist: String,
    pub rules: Option<String>,
    pub bssid: Option<String>,
}

/// Wireless attack type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WirelessAttackType {
    Deauth,
    HandshakeCapture,
    PmkidCapture,
    WpsPixieDust,
    WpsBruteforce,
    EvilTwin,
}

/// Wireless attack status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AttackStatus {
    Pending,
    Running,
    Success,
    Failed,
    Cancelled,
}

/// Wireless attack result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessAttack {
    pub id: String,
    pub attack_type: WirelessAttackType,
    pub target_bssid: String,
    pub target_ssid: Option<String>,
    pub status: AttackStatus,
    pub result: Option<String>,
    pub capture_file: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Crack job status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrackStatus {
    Pending,
    Running,
    Success,
    Exhausted,  // Wordlist exhausted, no password found
    Failed,
    Cancelled,
}

/// Crack job result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackJob {
    pub id: String,
    pub capture_id: String,
    pub capture_type: String,  // handshake or pmkid
    pub status: CrackStatus,
    pub wordlist: String,
    pub keys_tested: u64,
    pub keys_per_second: f64,
    pub password: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Wireless scan session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessScan {
    pub id: String,
    pub user_id: String,
    pub interface: String,
    pub config: WirelessScanConfig,
    pub status: AttackStatus,
    pub networks_found: u32,
    pub clients_found: u32,
    pub handshakes_captured: u32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// API request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartScanRequest {
    pub interface: String,
    pub channels: Option<Vec<u8>>,
    pub duration_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthRequest {
    pub interface: String,
    pub bssid: String,
    pub client: Option<String>,
    pub count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRequest {
    pub interface: String,
    pub bssid: String,
    pub channel: u8,
    pub timeout_secs: Option<u32>,
    pub use_deauth: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackRequest {
    pub capture_id: String,
    pub wordlist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsAttackRequest {
    pub interface: String,
    pub bssid: String,
    pub use_pixie_dust: Option<bool>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessDashboardStats {
    pub total_scans: u32,
    pub active_scans: u32,
    pub networks_discovered: u32,
    pub handshakes_captured: u32,
    pub pmkids_captured: u32,
    pub passwords_cracked: u32,
    pub networks_by_encryption: std::collections::HashMap<String, u32>,
    pub top_vulnerable_networks: Vec<VulnerableNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableNetwork {
    pub ssid: String,
    pub bssid: String,
    pub encryption: WirelessEncryption,
    pub vulnerability: String,
    pub severity: String,
}

/// Evil twin detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinDetection {
    pub ssid: String,
    pub legitimate_bssid: String,
    pub suspicious_bssid: String,
    pub reason: String,
    pub detected_at: DateTime<Utc>,
}
