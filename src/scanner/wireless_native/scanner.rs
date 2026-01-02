//! Wireless network scanner
//!
//! Discovers access points and clients using monitor mode.

use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::monitor::MonitorManager;
use super::types::*;

/// Wireless network scanner
pub struct WirelessScanner {
    /// Monitor manager
    monitor: MonitorManager,
    /// Scan configuration
    config: WirelessScanConfig,
    /// Discovered access points
    access_points: Arc<Mutex<HashMap<String, AccessPoint>>>,
    /// Discovered clients
    clients: Arc<Mutex<HashMap<String, WirelessClient>>>,
    /// Captured handshakes
    handshakes: Arc<Mutex<Vec<CapturedHandshake>>>,
    /// Captured PMKIDs
    pmkids: Arc<Mutex<Vec<PmkidData>>>,
    /// Is scanning
    is_scanning: Arc<Mutex<bool>>,
    /// Packets captured
    packet_count: Arc<Mutex<u64>>,
}

impl WirelessScanner {
    /// Create new wireless scanner
    pub fn new(config: WirelessScanConfig) -> Self {
        Self {
            monitor: MonitorManager::new(&config.interface),
            config,
            access_points: Arc::new(Mutex::new(HashMap::new())),
            clients: Arc::new(Mutex::new(HashMap::new())),
            handshakes: Arc::new(Mutex::new(Vec::new())),
            pmkids: Arc::new(Mutex::new(Vec::new())),
            is_scanning: Arc::new(Mutex::new(false)),
            packet_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Start scanning
    pub fn start(&mut self) -> Result<()> {
        // Enable monitor mode
        let _mon_iface = self.monitor.enable()?;

        *self.is_scanning.lock().unwrap() = true;

        // Start channel hopping in background if multiple channels
        if self.config.channels.len() > 1 {
            self.start_channel_hopper()?;
        } else if let Some(&channel) = self.config.channels.first() {
            self.monitor.set_channel(channel)?;
        }

        // Start packet capture
        self.start_capture()?;

        Ok(())
    }

    /// Stop scanning
    pub fn stop(&mut self) -> Result<WirelessScanResult> {
        *self.is_scanning.lock().unwrap() = false;

        // Disable monitor mode
        self.monitor.disable()?;

        // Collect results
        let access_points = self.access_points.lock().unwrap()
            .values()
            .cloned()
            .collect();

        let clients = self.clients.lock().unwrap()
            .values()
            .cloned()
            .collect();

        let handshakes = self.handshakes.lock().unwrap().clone();
        let pmkids = self.pmkids.lock().unwrap().clone();
        let packets_captured = *self.packet_count.lock().unwrap();

        Ok(WirelessScanResult {
            access_points,
            clients,
            handshakes,
            pmkids,
            start_time: None,
            end_time: Some(Utc::now()),
            packets_captured,
            errors: Vec::new(),
        })
    }

    /// Start channel hopper
    fn start_channel_hopper(&self) -> Result<()> {
        let channels = self.config.channels.clone();
        let hop_interval = Duration::from_millis(self.config.hop_interval_ms as u64);
        let is_scanning = self.is_scanning.clone();
        let monitor_iface = self.monitor.get_monitor_interface()
            .ok_or_else(|| anyhow!("Monitor interface not enabled"))?
            .to_string();

        std::thread::spawn(move || {
            let mut channel_idx = 0;

            loop {
                if !*is_scanning.lock().unwrap() {
                    break;
                }

                let channel = channels[channel_idx % channels.len()];

                // Set channel using iw
                let _ = std::process::Command::new("iw")
                    .args(["dev", &monitor_iface, "set", "channel", &channel.to_string()])
                    .output();

                channel_idx += 1;
                std::thread::sleep(hop_interval);
            }
        });

        Ok(())
    }

    /// Start packet capture (simulated - would use libpcap or raw sockets)
    fn start_capture(&self) -> Result<()> {
        // In production, this would use:
        // 1. libpcap (via pcap crate) for portable packet capture
        // 2. AF_PACKET raw sockets on Linux
        // 3. Parse 802.11 frames and extract information

        // For now, this is a framework that shows the structure
        // Real implementation would capture actual packets

        let access_points = self.access_points.clone();
        let clients = self.clients.clone();
        let handshakes = self.handshakes.clone();
        let pmkids = self.pmkids.clone();
        let is_scanning = self.is_scanning.clone();
        let packet_count = self.packet_count.clone();
        let _config = self.config.clone();

        std::thread::spawn(move || {
            // This would be the packet capture loop
            // Using pcap::Capture or raw AF_PACKET socket

            while *is_scanning.lock().unwrap() {
                // Simulated - would read actual packets here
                // For each packet:
                // 1. Parse 802.11 header
                // 2. Identify frame type (beacon, probe, data, etc.)
                // 3. Extract relevant information
                // 4. Update access_points, clients, handshakes, pmkids

                *packet_count.lock().unwrap() += 1;

                // Example: would call these handlers for different frame types
                // handle_beacon_frame(&access_points, &frame);
                // handle_probe_request(&clients, &frame);
                // handle_eapol_frame(&handshakes, &frame);

                std::thread::sleep(Duration::from_millis(10));
            }

            let _ = access_points;
            let _ = clients;
            let _ = handshakes;
            let _ = pmkids;
        });

        Ok(())
    }

    /// Get current scan results (live)
    pub fn get_current_results(&self) -> WirelessScanResult {
        let access_points = self.access_points.lock().unwrap()
            .values()
            .cloned()
            .collect();

        let clients = self.clients.lock().unwrap()
            .values()
            .cloned()
            .collect();

        let handshakes = self.handshakes.lock().unwrap().clone();
        let pmkids = self.pmkids.lock().unwrap().clone();
        let packets_captured = *self.packet_count.lock().unwrap();

        WirelessScanResult {
            access_points,
            clients,
            handshakes,
            pmkids,
            start_time: None,
            end_time: None,
            packets_captured,
            errors: Vec::new(),
        }
    }

    /// Process a beacon frame
    pub fn process_beacon(&self, bssid: &str, ssid: Option<&str>, channel: u8,
                          signal: i8, security_info: &SecurityInfo) {
        let mut aps = self.access_points.lock().unwrap();
        let now = Utc::now();

        let ap = aps.entry(bssid.to_string()).or_insert_with(|| {
            AccessPoint {
                bssid: bssid.to_string(),
                ssid: ssid.map(|s| s.to_string()),
                hidden: ssid.is_none() || ssid.map(|s| s.is_empty()).unwrap_or(true),
                channel,
                frequency: channel_to_frequency(channel).unwrap_or(0),
                signal_dbm: signal,
                signal_quality: signal_to_quality(signal),
                security: security_info.security_type,
                ciphers: security_info.ciphers.clone(),
                auth_methods: security_info.auth_methods.clone(),
                wpa_versions: security_info.wpa_versions.clone(),
                wps_enabled: security_info.wps_enabled,
                wps_locked: false,
                manufacturer: get_manufacturer(bssid),
                clients: Vec::new(),
                first_seen: now,
                last_seen: now,
                beacon_count: 0,
                data_count: 0,
            }
        });

        ap.last_seen = now;
        ap.beacon_count += 1;
        ap.signal_dbm = signal;
        ap.signal_quality = signal_to_quality(signal);

        if ssid.is_some() && ap.ssid.is_none() {
            ap.ssid = ssid.map(|s| s.to_string());
            ap.hidden = false;
        }
    }

    /// Process a probe request
    pub fn process_probe_request(&self, client_mac: &str, ssid: Option<&str>, signal: i8) {
        let mut clients = self.clients.lock().unwrap();
        let now = Utc::now();

        let client = clients.entry(client_mac.to_string()).or_insert_with(|| {
            WirelessClient {
                mac_address: client_mac.to_string(),
                associated_bssid: None,
                signal_dbm: signal,
                manufacturer: get_manufacturer(client_mac),
                probes: Vec::new(),
                first_seen: now,
                last_seen: now,
                data_count: 0,
            }
        });

        client.last_seen = now;
        client.signal_dbm = signal;

        if let Some(ssid) = ssid {
            if !ssid.is_empty() && !client.probes.contains(&ssid.to_string()) {
                client.probes.push(ssid.to_string());
            }
        }
    }

    /// Process an EAPOL frame (part of 4-way handshake)
    pub fn process_eapol(&self, bssid: &str, client_mac: &str, ssid: &str,
                         message: EapolMessage) {
        let mut handshakes = self.handshakes.lock().unwrap();

        // Find existing handshake index
        let existing_idx = handshakes.iter()
            .position(|h| h.bssid == bssid && h.client_mac == client_mac);

        // Create new handshake if not found
        let hs_idx = match existing_idx {
            Some(idx) => idx,
            None => {
                handshakes.push(CapturedHandshake {
                    bssid: bssid.to_string(),
                    ssid: ssid.to_string(),
                    client_mac: client_mac.to_string(),
                    anonce: Vec::new(),
                    snonce: Vec::new(),
                    message1: None,
                    message2: None,
                    message3: None,
                    message4: None,
                    complete: false,
                    captured_at: Utc::now(),
                });
                handshakes.len() - 1
            }
        };

        if let Some(hs) = handshakes.get_mut(hs_idx) {
            match message.message_number {
                1 => {
                    hs.anonce = message.nonce.clone();
                    hs.message1 = Some(message);
                }
                2 => {
                    hs.snonce = message.nonce.clone();
                    hs.message2 = Some(message);
                }
                3 => {
                    hs.message3 = Some(message);
                }
                4 => {
                    hs.message4 = Some(message);
                    hs.complete = true;
                }
                _ => {}
            }

            hs.complete = hs.is_crackable();
        }
    }

    /// Process PMKID from association response or EAPOL message 1
    pub fn process_pmkid(&self, bssid: &str, client_mac: &str, ssid: &str, pmkid: Vec<u8>) {
        let mut pmkids = self.pmkids.lock().unwrap();

        // Check if we already have this PMKID
        let exists = pmkids.iter().any(|p| p.pmkid == pmkid);

        if !exists {
            pmkids.push(PmkidData {
                pmkid,
                bssid: bssid.to_string(),
                client_mac: client_mac.to_string(),
                ssid: ssid.to_string(),
                captured_at: Utc::now(),
            });
        }
    }
}

/// Security information extracted from beacon/probe response
#[derive(Debug, Clone, Default)]
pub struct SecurityInfo {
    pub security_type: SecurityType,
    pub ciphers: Vec<CipherSuite>,
    pub auth_methods: Vec<AuthMethod>,
    pub wpa_versions: Vec<WpaVersion>,
    pub wps_enabled: bool,
}

impl Default for SecurityType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Convert signal strength (dBm) to quality percentage
fn signal_to_quality(dbm: i8) -> u8 {
    // Typical range: -90 dBm (weak) to -30 dBm (strong)
    let quality = if dbm >= -50 {
        100
    } else if dbm <= -100 {
        0
    } else {
        (2 * (dbm + 100)) as u8
    };

    quality.min(100)
}

/// Get manufacturer from MAC address OUI
fn get_manufacturer(mac: &str) -> Option<String> {
    // Extract OUI (first 3 bytes)
    let oui = mac.replace(":", "").replace("-", "").to_uppercase();
    if oui.len() < 6 {
        return None;
    }

    let oui = &oui[..6];

    // Common OUIs (would have full database in production)
    let manufacturers: &[(&str, &str)] = &[
        ("00037F", "Atheros"),
        ("001122", "CIMSYS"),
        ("001A2B", "Ayecom"),
        ("001F3A", "Hon Hai/Foxconn"),
        ("00248C", "ASUSTek"),
        ("002456", "Zyxel"),
        ("0026F2", "Netgear"),
        ("002719", "TP-Link"),
        ("003012", "TRENDnet"),
        ("00904B", "Gemtek"),
        ("00C0CA", "Alfa"),
        ("0C8269", "Apple"),
        ("10BEF5", "D-Link"),
        ("147D05", "Samsung"),
        ("18FE34", "Espressif"),
        ("1C3BF3", "ASUSTek"),
        ("24A43C", "Ubiquiti"),
        ("30B5C2", "TP-Link"),
        ("4018B1", "Cisco"),
        ("5C5181", "Intel"),
        ("60A44C", "ASUSTek"),
        ("68FF7B", "TP-Link"),
        ("78D294", "TP-Link"),
        ("84D47E", "Hangzhou Hikvision"),
        ("889FFA", "Hon Hai/Foxconn"),
        ("9C5CF8", "Intel"),
        ("A4C494", "Intel"),
        ("AC220B", "ASUSTek"),
        ("B4E62D", "TP-Link"),
        ("C46E1F", "TP-Link"),
        ("D46A6A", "TP-Link"),
        ("E4F4C6", "Netgear"),
        ("F4F26D", "TP-Link"),
    ];

    manufacturers.iter()
        .find(|(prefix, _)| oui.starts_with(prefix))
        .map(|(_, name)| name.to_string())
}

/// Parse 802.11 Information Element
pub fn parse_ie(data: &[u8]) -> Vec<InformationElement> {
    let mut elements = Vec::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let id = data[pos];
        let len = data[pos + 1] as usize;

        if pos + 2 + len > data.len() {
            break;
        }

        let ie_data = &data[pos + 2..pos + 2 + len];

        elements.push(InformationElement {
            id,
            data: ie_data.to_vec(),
        });

        pos += 2 + len;
    }

    elements
}

/// Information Element
#[derive(Debug, Clone)]
pub struct InformationElement {
    pub id: u8,
    pub data: Vec<u8>,
}

/// Well-known IE IDs
pub mod ie_ids {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const DS_PARAMETER: u8 = 3;
    pub const TIM: u8 = 5;
    pub const COUNTRY: u8 = 7;
    pub const RSN: u8 = 48;
    pub const VENDOR_SPECIFIC: u8 = 221;
}

/// Parse RSN (WPA2) Information Element
pub fn parse_rsn_ie(data: &[u8]) -> Result<SecurityInfo> {
    if data.len() < 10 {
        return Err(anyhow!("RSN IE too short"));
    }

    let mut info = SecurityInfo::default();
    info.security_type = SecurityType::WPA2;
    info.wpa_versions.push(WpaVersion::Wpa2);

    let mut pos = 0;

    // Version (2 bytes)
    let _version = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Group cipher suite (4 bytes)
    if pos + 4 <= data.len() {
        let cipher_oui = &data[pos..pos + 3];
        let cipher_type = data[pos + 3];

        if cipher_oui == [0x00, 0x0F, 0xAC] {
            info.ciphers.push(match cipher_type {
                1 => CipherSuite::Wep40,
                2 => CipherSuite::Tkip,
                4 => CipherSuite::Ccmp,
                5 => CipherSuite::Wep104,
                8 => CipherSuite::Gcmp128,
                9 => CipherSuite::Gcmp256,
                _ => CipherSuite::Ccmp,
            });
        }
        pos += 4;
    }

    // Pairwise cipher count and suites
    if pos + 2 <= data.len() {
        let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        for _ in 0..count {
            if pos + 4 > data.len() {
                break;
            }
            let cipher_type = data[pos + 3];
            if !info.ciphers.iter().any(|c| *c == match cipher_type {
                2 => CipherSuite::Tkip,
                4 => CipherSuite::Ccmp,
                8 => CipherSuite::Gcmp128,
                9 => CipherSuite::Gcmp256,
                _ => CipherSuite::Ccmp,
            }) {
                info.ciphers.push(match cipher_type {
                    2 => CipherSuite::Tkip,
                    4 => CipherSuite::Ccmp,
                    8 => CipherSuite::Gcmp128,
                    9 => CipherSuite::Gcmp256,
                    _ => CipherSuite::Ccmp,
                });
            }
            pos += 4;
        }
    }

    // AKM count and suites
    if pos + 2 <= data.len() {
        let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        for _ in 0..count {
            if pos + 4 > data.len() {
                break;
            }
            let akm_type = data[pos + 3];
            info.auth_methods.push(match akm_type {
                1 => AuthMethod::Eap,
                2 => AuthMethod::Psk,
                3 => AuthMethod::Ft,
                5 => AuthMethod::EapSha256,
                6 => AuthMethod::Psk, // PSK-SHA256
                8 => AuthMethod::Sae,
                9 => AuthMethod::FtSae,
                _ => AuthMethod::Psk,
            });
            pos += 4;
        }
    }

    // Check for WPA3
    if info.auth_methods.contains(&AuthMethod::Sae) {
        info.security_type = SecurityType::WPA3;
        info.wpa_versions.push(WpaVersion::Wpa3);
    }

    Ok(info)
}

/// Parse WPA (vendor specific) Information Element
pub fn parse_wpa_ie(data: &[u8]) -> Result<SecurityInfo> {
    // WPA IE is vendor specific (221) with Microsoft OUI
    if data.len() < 8 {
        return Err(anyhow!("WPA IE too short"));
    }

    // Skip OUI (00:50:F2) and type (1)
    if &data[0..3] != [0x00, 0x50, 0xF2] || data[3] != 1 {
        return Err(anyhow!("Not a WPA IE"));
    }

    let mut info = SecurityInfo::default();
    info.security_type = SecurityType::WPA;
    info.wpa_versions.push(WpaVersion::Wpa1);

    // Similar parsing to RSN but starting at offset 4
    let rsn_data = &data[4..];
    if let Ok(rsn_info) = parse_rsn_ie(rsn_data) {
        info.ciphers = rsn_info.ciphers;
        info.auth_methods = rsn_info.auth_methods;
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_to_quality() {
        assert_eq!(signal_to_quality(-30), 100);
        assert_eq!(signal_to_quality(-50), 100);
        assert_eq!(signal_to_quality(-100), 0);
        assert!(signal_to_quality(-75) > 0);
        assert!(signal_to_quality(-75) < 100);
    }

    #[test]
    fn test_manufacturer_lookup() {
        assert_eq!(get_manufacturer("00:27:19:11:22:33"), Some("TP-Link".to_string()));
        assert_eq!(get_manufacturer("24:A4:3C:11:22:33"), Some("Ubiquiti".to_string()));
    }
}
