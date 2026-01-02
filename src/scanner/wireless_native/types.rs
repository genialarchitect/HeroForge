//! Wireless security types and data structures
//!
//! Core types for native wireless security analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wireless interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessInterface {
    /// Interface name (e.g., wlan0)
    pub name: String,
    /// Driver name
    pub driver: String,
    /// Chipset information
    pub chipset: Option<String>,
    /// Current mode (managed, monitor, etc.)
    pub mode: InterfaceMode,
    /// MAC address
    pub mac_address: String,
    /// Supported frequencies
    pub supported_frequencies: Vec<u32>,
    /// Monitor mode capable
    pub monitor_capable: bool,
    /// Injection capable
    pub injection_capable: bool,
}

/// Interface operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceMode {
    Managed,
    Monitor,
    Master,
    Adhoc,
    Unknown,
}

impl std::fmt::Display for InterfaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Managed => write!(f, "Managed"),
            Self::Monitor => write!(f, "Monitor"),
            Self::Master => write!(f, "Master"),
            Self::Adhoc => write!(f, "Ad-hoc"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Access point information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    /// BSSID (MAC address of AP)
    pub bssid: String,
    /// SSID (network name)
    pub ssid: Option<String>,
    /// Is hidden SSID
    pub hidden: bool,
    /// Channel number
    pub channel: u8,
    /// Frequency in MHz
    pub frequency: u32,
    /// Signal strength (dBm)
    pub signal_dbm: i8,
    /// Signal quality (0-100)
    pub signal_quality: u8,
    /// Security type
    pub security: SecurityType,
    /// Encryption ciphers
    pub ciphers: Vec<CipherSuite>,
    /// Authentication methods
    pub auth_methods: Vec<AuthMethod>,
    /// WPA version(s)
    pub wpa_versions: Vec<WpaVersion>,
    /// WPS enabled
    pub wps_enabled: bool,
    /// WPS locked
    pub wps_locked: bool,
    /// Manufacturer (from OUI)
    pub manufacturer: Option<String>,
    /// Connected clients
    pub clients: Vec<WirelessClient>,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Beacons captured
    pub beacon_count: u32,
    /// Data packets captured
    pub data_count: u32,
}

/// Security type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityType {
    Open,
    WEP,
    WPA,
    WPA2,
    WPA3,
    WpaWpa2Mixed,
    Wpa2Wpa3Mixed,
    Unknown,
}

impl std::fmt::Display for SecurityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::WEP => write!(f, "WEP"),
            Self::WPA => write!(f, "WPA"),
            Self::WPA2 => write!(f, "WPA2"),
            Self::WPA3 => write!(f, "WPA3"),
            Self::WpaWpa2Mixed => write!(f, "WPA/WPA2"),
            Self::Wpa2Wpa3Mixed => write!(f, "WPA2/WPA3"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// WPA version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WpaVersion {
    Wpa1,
    Wpa2,
    Wpa3,
}

/// Cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// WEP-40
    Wep40,
    /// WEP-104
    Wep104,
    /// TKIP
    Tkip,
    /// CCMP (AES)
    Ccmp,
    /// GCMP-128
    Gcmp128,
    /// GCMP-256
    Gcmp256,
    /// BIP-CMAC-128
    BipCmac128,
    /// BIP-GMAC-128
    BipGmac128,
    /// BIP-GMAC-256
    BipGmac256,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wep40 => write!(f, "WEP-40"),
            Self::Wep104 => write!(f, "WEP-104"),
            Self::Tkip => write!(f, "TKIP"),
            Self::Ccmp => write!(f, "CCMP"),
            Self::Gcmp128 => write!(f, "GCMP-128"),
            Self::Gcmp256 => write!(f, "GCMP-256"),
            Self::BipCmac128 => write!(f, "BIP-CMAC-128"),
            Self::BipGmac128 => write!(f, "BIP-GMAC-128"),
            Self::BipGmac256 => write!(f, "BIP-GMAC-256"),
        }
    }
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Open,
    SharedKey,
    Psk,
    Sae,
    Eap,
    EapSha256,
    EapSha384,
    Ft,
    FtSae,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "Open"),
            Self::SharedKey => write!(f, "Shared Key"),
            Self::Psk => write!(f, "PSK"),
            Self::Sae => write!(f, "SAE"),
            Self::Eap => write!(f, "802.1X"),
            Self::EapSha256 => write!(f, "802.1X-SHA256"),
            Self::EapSha384 => write!(f, "802.1X-SHA384"),
            Self::Ft => write!(f, "FT"),
            Self::FtSae => write!(f, "FT-SAE"),
        }
    }
}

/// Wireless client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessClient {
    /// Client MAC address
    pub mac_address: String,
    /// Associated BSSID (if any)
    pub associated_bssid: Option<String>,
    /// Signal strength
    pub signal_dbm: i8,
    /// Manufacturer (from OUI)
    pub manufacturer: Option<String>,
    /// Probe requests (SSIDs the client is looking for)
    pub probes: Vec<String>,
    /// First seen
    pub first_seen: DateTime<Utc>,
    /// Last seen
    pub last_seen: DateTime<Utc>,
    /// Data packets
    pub data_count: u32,
}

/// Captured WPA handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedHandshake {
    /// BSSID of the access point
    pub bssid: String,
    /// SSID of the network
    pub ssid: String,
    /// Client MAC address
    pub client_mac: String,
    /// ANonce (AP nonce)
    pub anonce: Vec<u8>,
    /// SNonce (Station/client nonce)
    pub snonce: Vec<u8>,
    /// Message 1 of 4-way handshake
    pub message1: Option<EapolMessage>,
    /// Message 2 of 4-way handshake
    pub message2: Option<EapolMessage>,
    /// Message 3 of 4-way handshake
    pub message3: Option<EapolMessage>,
    /// Message 4 of 4-way handshake
    pub message4: Option<EapolMessage>,
    /// Is handshake complete
    pub complete: bool,
    /// Capture timestamp
    pub captured_at: DateTime<Utc>,
}

impl CapturedHandshake {
    /// Check if handshake is valid for cracking
    pub fn is_crackable(&self) -> bool {
        // Need at least messages 1&2 or 2&3 for cracking
        let has_m1_m2 = self.message1.is_some() && self.message2.is_some();
        let has_m2_m3 = self.message2.is_some() && self.message3.is_some();

        has_m1_m2 || has_m2_m3
    }

    /// Get minimum required handshake messages for cracking
    pub fn get_crack_data(&self) -> Option<HandshakeCrackData> {
        if let (Some(m2), anonce) = (&self.message2, &self.anonce) {
            Some(HandshakeCrackData {
                bssid: self.bssid.clone(),
                ssid: self.ssid.clone(),
                client_mac: self.client_mac.clone(),
                anonce: anonce.clone(),
                snonce: self.snonce.clone(),
                mic: m2.mic.clone(),
                key_data: m2.key_data.clone(),
            })
        } else {
            None
        }
    }
}

/// Data needed for handshake cracking
#[derive(Debug, Clone)]
pub struct HandshakeCrackData {
    /// BSSID
    pub bssid: String,
    /// SSID
    pub ssid: String,
    /// Client MAC
    pub client_mac: String,
    /// ANonce
    pub anonce: Vec<u8>,
    /// SNonce
    pub snonce: Vec<u8>,
    /// MIC from message 2
    pub mic: Vec<u8>,
    /// Key data from message 2
    pub key_data: Vec<u8>,
}

/// EAPOL key message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapolMessage {
    /// Message number (1-4)
    pub message_number: u8,
    /// Key descriptor type
    pub key_type: u8,
    /// Key information
    pub key_info: u16,
    /// Key length
    pub key_length: u16,
    /// Replay counter
    pub replay_counter: u64,
    /// Key nonce
    pub nonce: Vec<u8>,
    /// Key IV
    pub key_iv: Vec<u8>,
    /// Key RSC
    pub key_rsc: Vec<u8>,
    /// Key MIC
    pub mic: Vec<u8>,
    /// Key data
    pub key_data: Vec<u8>,
    /// Raw packet data
    pub raw_data: Vec<u8>,
}

/// PMKID data for hashcat-style attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmkidData {
    /// PMKID value
    pub pmkid: Vec<u8>,
    /// BSSID
    pub bssid: String,
    /// Client MAC
    pub client_mac: String,
    /// SSID
    pub ssid: String,
    /// Capture timestamp
    pub captured_at: DateTime<Utc>,
}

impl PmkidData {
    /// Format PMKID for hashcat (mode 22000)
    pub fn to_hashcat_format(&self) -> String {
        let pmkid_hex = hex::encode(&self.pmkid);
        let bssid_hex = self.bssid.replace(":", "").to_lowercase();
        let client_hex = self.client_mac.replace(":", "").to_lowercase();
        let ssid_hex = hex::encode(self.ssid.as_bytes());

        format!(
            "WPA*02*{}*{}*{}*{}",
            pmkid_hex, bssid_hex, client_hex, ssid_hex
        )
    }
}

/// Scan configuration
#[derive(Debug, Clone)]
pub struct WirelessScanConfig {
    /// Interface to use
    pub interface: String,
    /// Channels to scan (empty = all)
    pub channels: Vec<u8>,
    /// Channel hop interval (ms)
    pub hop_interval_ms: u32,
    /// Scan duration (seconds, 0 = indefinite)
    pub duration_secs: u32,
    /// Capture handshakes
    pub capture_handshakes: bool,
    /// Capture PMKID
    pub capture_pmkid: bool,
    /// Active probing
    pub active_probe: bool,
    /// Hidden SSID discovery
    pub discover_hidden: bool,
    /// Filter by BSSID
    pub bssid_filter: Option<String>,
    /// Filter by SSID
    pub ssid_filter: Option<String>,
}

impl Default for WirelessScanConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            channels: vec![1, 6, 11], // Common 2.4GHz channels
            hop_interval_ms: 500,
            duration_secs: 30,
            capture_handshakes: true,
            capture_pmkid: true,
            active_probe: false,
            discover_hidden: true,
            bssid_filter: None,
            ssid_filter: None,
        }
    }
}

/// Scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WirelessScanResult {
    /// Discovered access points
    pub access_points: Vec<AccessPoint>,
    /// Discovered clients
    pub clients: Vec<WirelessClient>,
    /// Captured handshakes
    pub handshakes: Vec<CapturedHandshake>,
    /// Captured PMKIDs
    pub pmkids: Vec<PmkidData>,
    /// Scan start time
    pub start_time: Option<DateTime<Utc>>,
    /// Scan end time
    pub end_time: Option<DateTime<Utc>>,
    /// Total packets captured
    pub packets_captured: u64,
    /// Scan errors
    pub errors: Vec<String>,
}

/// Rogue AP detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueApDetection {
    /// Detected rogue AP
    pub rogue_ap: AccessPoint,
    /// Legitimate AP (if known)
    pub legitimate_ap: Option<AccessPoint>,
    /// Detection type
    pub detection_type: RogueApType,
    /// Confidence score (0-100)
    pub confidence: u8,
    /// Detection reason
    pub reason: String,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
}

/// Type of rogue AP detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RogueApType {
    /// Same SSID, different BSSID
    SsidDuplicate,
    /// Evil twin (exact clone)
    EvilTwin,
    /// Karma attack (responds to all probes)
    KarmaAttack,
    /// Unauthorized AP on network
    UnauthorizedAp,
    /// MAC address spoofing
    MacSpoofing,
}

impl std::fmt::Display for RogueApType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SsidDuplicate => write!(f, "SSID Duplicate"),
            Self::EvilTwin => write!(f, "Evil Twin"),
            Self::KarmaAttack => write!(f, "Karma Attack"),
            Self::UnauthorizedAp => write!(f, "Unauthorized AP"),
            Self::MacSpoofing => write!(f, "MAC Spoofing"),
        }
    }
}

/// Security assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessSecurityAssessment {
    /// Target access point
    pub access_point: AccessPoint,
    /// Security rating (0-100)
    pub security_rating: u8,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<WirelessVulnerability>,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Assessment timestamp
    pub assessed_at: DateTime<Utc>,
}

/// Wireless vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessVulnerability {
    /// Vulnerability type
    pub vuln_type: WirelessVulnType,
    /// Severity (1-10)
    pub severity: u8,
    /// Description
    pub description: String,
    /// CVE reference (if applicable)
    pub cve: Option<String>,
    /// Exploitable
    pub exploitable: bool,
}

/// Wireless vulnerability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WirelessVulnType {
    /// WEP encryption (broken)
    WeakEncryptionWep,
    /// TKIP encryption (deprecated)
    WeakEncryptionTkip,
    /// WPA1 (deprecated)
    DeprecatedWpa1,
    /// No encryption
    NoEncryption,
    /// WPS enabled
    WpsEnabled,
    /// WPS PIN brute-force possible
    WpsPinBruteforce,
    /// PMKID capturable
    PmkidCapturable,
    /// Weak password (if cracked)
    WeakPassword,
    /// Management frame protection disabled
    NoMfp,
    /// KRACK vulnerability
    Krack,
    /// Dragonblood (WPA3 vulnerability)
    Dragonblood,
    /// FragAttacks
    FragAttacks,
}

impl std::fmt::Display for WirelessVulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakEncryptionWep => write!(f, "WEP Encryption"),
            Self::WeakEncryptionTkip => write!(f, "TKIP Encryption"),
            Self::DeprecatedWpa1 => write!(f, "Deprecated WPA1"),
            Self::NoEncryption => write!(f, "No Encryption"),
            Self::WpsEnabled => write!(f, "WPS Enabled"),
            Self::WpsPinBruteforce => write!(f, "WPS PIN Bruteforce"),
            Self::PmkidCapturable => write!(f, "PMKID Capturable"),
            Self::WeakPassword => write!(f, "Weak Password"),
            Self::NoMfp => write!(f, "No Management Frame Protection"),
            Self::Krack => write!(f, "KRACK Vulnerability"),
            Self::Dragonblood => write!(f, "Dragonblood (WPA3)"),
            Self::FragAttacks => write!(f, "FragAttacks"),
        }
    }
}

/// Deauthentication attack configuration
#[derive(Debug, Clone)]
pub struct DeauthConfig {
    /// Target BSSID
    pub bssid: String,
    /// Target client (None = broadcast)
    pub client_mac: Option<String>,
    /// Number of deauth packets
    pub count: u32,
    /// Interval between packets (ms)
    pub interval_ms: u32,
    /// Reason code
    pub reason_code: u16,
}

impl Default for DeauthConfig {
    fn default() -> Self {
        Self {
            bssid: String::new(),
            client_mac: None,
            count: 10,
            interval_ms: 100,
            reason_code: 7, // Class 3 frame received from non-associated station
        }
    }
}

/// IEEE 802.11 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management,
    Control,
    Data,
}

/// IEEE 802.11 management frame subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
}

/// OUI vendor database entry
#[derive(Debug, Clone)]
pub struct OuiVendor {
    /// OUI prefix (first 3 bytes of MAC)
    pub oui: [u8; 3],
    /// Vendor name
    pub vendor: String,
}

/// Channel information
#[derive(Debug, Clone, Copy)]
pub struct ChannelInfo {
    /// Channel number
    pub number: u8,
    /// Frequency (MHz)
    pub frequency: u32,
    /// Band (2.4GHz or 5GHz)
    pub band: WifiBand,
    /// Channel width
    pub width: ChannelWidth,
}

/// WiFi frequency band
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiBand {
    /// 2.4 GHz
    Band24Ghz,
    /// 5 GHz
    Band5Ghz,
    /// 6 GHz (WiFi 6E)
    Band6Ghz,
}

/// Channel width
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelWidth {
    /// 20 MHz
    Width20Mhz,
    /// 40 MHz
    Width40Mhz,
    /// 80 MHz
    Width80Mhz,
    /// 160 MHz
    Width160Mhz,
}

/// Convert channel number to frequency
pub fn channel_to_frequency(channel: u8) -> Option<u32> {
    match channel {
        // 2.4 GHz band
        1..=14 => {
            if channel == 14 {
                Some(2484)
            } else {
                Some(2407 + (channel as u32 * 5))
            }
        }
        // 5 GHz band
        36 => Some(5180),
        40 => Some(5200),
        44 => Some(5220),
        48 => Some(5240),
        52 => Some(5260),
        56 => Some(5280),
        60 => Some(5300),
        64 => Some(5320),
        100 => Some(5500),
        104 => Some(5520),
        108 => Some(5540),
        112 => Some(5560),
        116 => Some(5580),
        120 => Some(5600),
        124 => Some(5620),
        128 => Some(5640),
        132 => Some(5660),
        136 => Some(5680),
        140 => Some(5700),
        144 => Some(5720),
        149 => Some(5745),
        153 => Some(5765),
        157 => Some(5785),
        161 => Some(5805),
        165 => Some(5825),
        _ => None,
    }
}

/// Convert frequency to channel number
pub fn frequency_to_channel(freq: u32) -> Option<u8> {
    match freq {
        // 2.4 GHz
        2412 => Some(1),
        2417 => Some(2),
        2422 => Some(3),
        2427 => Some(4),
        2432 => Some(5),
        2437 => Some(6),
        2442 => Some(7),
        2447 => Some(8),
        2452 => Some(9),
        2457 => Some(10),
        2462 => Some(11),
        2467 => Some(12),
        2472 => Some(13),
        2484 => Some(14),
        // 5 GHz
        5180 => Some(36),
        5200 => Some(40),
        5220 => Some(44),
        5240 => Some(48),
        5260 => Some(52),
        5280 => Some(56),
        5300 => Some(60),
        5320 => Some(64),
        5500 => Some(100),
        5520 => Some(104),
        5540 => Some(108),
        5560 => Some(112),
        5580 => Some(116),
        5600 => Some(120),
        5620 => Some(124),
        5640 => Some(128),
        5660 => Some(132),
        5680 => Some(136),
        5700 => Some(140),
        5720 => Some(144),
        5745 => Some(149),
        5765 => Some(153),
        5785 => Some(157),
        5805 => Some(161),
        5825 => Some(165),
        _ => None,
    }
}
