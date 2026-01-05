//! Wireless network scanner
//!
//! Discovers access points and clients using monitor mode.
//! Uses libpcap for real 802.11 frame capture and parsing.

use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::monitor::MonitorManager;
use super::types::*;

/// 802.11 Frame Control field constants
mod ieee80211 {
    // Frame type (bits 2-3)
    pub const TYPE_MANAGEMENT: u8 = 0;
    pub const TYPE_CONTROL: u8 = 1;
    pub const TYPE_DATA: u8 = 2;

    // Management frame subtypes (bits 4-7)
    pub const SUBTYPE_ASSOC_REQ: u8 = 0;
    pub const SUBTYPE_ASSOC_RESP: u8 = 1;
    pub const SUBTYPE_REASSOC_REQ: u8 = 2;
    pub const SUBTYPE_REASSOC_RESP: u8 = 3;
    pub const SUBTYPE_PROBE_REQ: u8 = 4;
    pub const SUBTYPE_PROBE_RESP: u8 = 5;
    pub const SUBTYPE_BEACON: u8 = 8;
    pub const SUBTYPE_DISASSOC: u8 = 10;
    pub const SUBTYPE_AUTH: u8 = 11;
    pub const SUBTYPE_DEAUTH: u8 = 12;
    pub const SUBTYPE_ACTION: u8 = 13;

    // Data frame subtypes
    pub const SUBTYPE_DATA: u8 = 0;
    pub const SUBTYPE_QOS_DATA: u8 = 8;

    // EAPOL EtherType
    pub const ETHERTYPE_EAPOL: u16 = 0x888E;

    // Frame control flags
    pub const FC_TO_DS: u8 = 0x01;
    pub const FC_FROM_DS: u8 = 0x02;
}

/// Parsed 802.11 frame header
#[derive(Debug, Clone)]
struct Frame80211 {
    /// Frame type (management, control, data)
    frame_type: u8,
    /// Frame subtype
    subtype: u8,
    /// To DS flag
    to_ds: bool,
    /// From DS flag
    from_ds: bool,
    /// Address 1 (receiver/destination)
    addr1: [u8; 6],
    /// Address 2 (transmitter/source)
    addr2: [u8; 6],
    /// Address 3 (BSSID or other)
    addr3: [u8; 6],
    /// Address 4 (optional, for WDS)
    addr4: Option<[u8; 6]>,
    /// Sequence control
    seq_ctrl: u16,
    /// Frame body (payload)
    body: Vec<u8>,
    /// Signal strength (from radiotap)
    signal_dbm: Option<i8>,
    /// Channel (from radiotap)
    channel: Option<u8>,
}

impl Frame80211 {
    /// Get BSSID based on frame direction flags
    fn get_bssid(&self) -> [u8; 6] {
        match (self.to_ds, self.from_ds) {
            (false, false) => self.addr3,  // IBSS/Ad-hoc
            (false, true) => self.addr2,   // From AP to client
            (true, false) => self.addr1,   // From client to AP
            (true, true) => self.addr3,    // WDS
        }
    }

    /// Get source address based on frame direction flags
    fn get_src(&self) -> [u8; 6] {
        match (self.to_ds, self.from_ds) {
            (false, false) => self.addr2,
            (false, true) => self.addr3,
            (true, false) => self.addr2,
            (true, true) => self.addr4.unwrap_or(self.addr2),
        }
    }

    /// Get destination address based on frame direction flags
    fn get_dst(&self) -> [u8; 6] {
        match (self.to_ds, self.from_ds) {
            (false, false) => self.addr1,
            (false, true) => self.addr1,
            (true, false) => self.addr3,
            (true, true) => self.addr3,
        }
    }
}

/// Format MAC address bytes as string
fn format_mac(addr: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

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

    /// Start packet capture using libpcap
    fn start_capture(&self) -> Result<()> {
        let monitor_iface = self.monitor.get_monitor_interface()
            .ok_or_else(|| anyhow!("Monitor interface not enabled"))?
            .to_string();

        let access_points = self.access_points.clone();
        let clients = self.clients.clone();
        let handshakes = self.handshakes.clone();
        let pmkids = self.pmkids.clone();
        let is_scanning = self.is_scanning.clone();
        let packet_count = self.packet_count.clone();
        let config = self.config.clone();

        std::thread::spawn(move || {
            // Open pcap capture on monitor interface
            let cap_result = pcap::Capture::from_device(monitor_iface.as_str())
                .map(|c| c.promisc(true)
                    .snaplen(65535)
                    .timeout(100)  // 100ms read timeout
                    .rfmon(true)   // Enable monitor mode (redundant but explicit)
                    .open());

            let mut cap = match cap_result {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    log::error!("Failed to open pcap capture: {}", e);
                    return;
                }
                Err(e) => {
                    log::error!("Failed to find capture device: {}", e);
                    return;
                }
            };

            // Set BPF filter for 802.11 frames (optional, depends on link type)
            // For radiotap, we capture all frames
            let datalink = cap.get_datalink();
            log::debug!("Capture datalink type: {:?}", datalink);

            // Main capture loop
            while *is_scanning.lock().unwrap() {
                match cap.next_packet() {
                    Ok(packet) => {
                        *packet_count.lock().unwrap() += 1;

                        // Parse the packet (radiotap header + 802.11 frame)
                        if let Some(frame) = parse_radiotap_and_80211(packet.data) {
                            // Apply BSSID filter if configured
                            if let Some(ref filter_bssid) = config.bssid_filter {
                                let frame_bssid = format_mac(&frame.get_bssid());
                                if !frame_bssid.eq_ignore_ascii_case(filter_bssid) {
                                    continue;
                                }
                            }

                            // Process based on frame type
                            match frame.frame_type {
                                ieee80211::TYPE_MANAGEMENT => {
                                    handle_management_frame(
                                        &frame,
                                        &access_points,
                                        &clients,
                                        &config,
                                    );
                                }
                                ieee80211::TYPE_DATA => {
                                    handle_data_frame(
                                        &frame,
                                        &access_points,
                                        &clients,
                                        &handshakes,
                                        &pmkids,
                                        &config,
                                    );
                                }
                                _ => {
                                    // Control frames are generally not processed
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal timeout, continue loop
                        continue;
                    }
                    Err(e) => {
                        log::error!("Packet capture error: {}", e);
                        break;
                    }
                }
            }

            log::debug!("Capture loop ended, processed {} packets",
                       *packet_count.lock().unwrap());
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

    // Comprehensive IEEE OUI database (500+ entries covering major manufacturers)
    // Format: (OUI prefix, Manufacturer name)
    static OUI_DATABASE: &[(&str, &str)] = &[
        // Apple
        ("00034F", "Apple"), ("000502", "Apple"), ("000A27", "Apple"), ("000A95", "Apple"),
        ("001124", "Apple"), ("001451", "Apple"), ("0016CB", "Apple"), ("0017F2", "Apple"),
        ("0019E3", "Apple"), ("001B63", "Apple"), ("001CB3", "Apple"), ("001D4F", "Apple"),
        ("001E52", "Apple"), ("001F5B", "Apple"), ("001FF3", "Apple"), ("0021E9", "Apple"),
        ("002312", "Apple"), ("002436", "Apple"), ("00254B", "Apple"), ("0026BB", "Apple"),
        ("003065", "Apple"), ("0050E4", "Apple"), ("041E64", "Apple"), ("04F7E4", "Apple"),
        ("086698", "Apple"), ("0C4DE9", "Apple"), ("0C8269", "Apple"), ("0CD746", "Apple"),
        ("109ADD", "Apple"), ("10DDB1", "Apple"), ("14205E", "Apple"), ("149F3C", "Apple"),
        ("182032", "Apple"), ("1C36BB", "Apple"), ("1C9E46", "Apple"), ("20A2E4", "Apple"),
        ("24A074", "Apple"), ("24A2E1", "Apple"), ("24E314", "Apple"), ("28CFDA", "Apple"),
        ("286ABA", "Apple"), ("2C1F23", "Apple"), ("2CBE08", "Apple"), ("3010E4", "Apple"),
        ("34159E", "Apple"), ("34C059", "Apple"), ("3C0754", "Apple"), ("3C15C2", "Apple"),
        ("3CE072", "Apple"), ("40331A", "Apple"), ("40A6D9", "Apple"), ("44D884", "Apple"),
        ("48437C", "Apple"), ("48746E", "Apple"), ("48A195", "Apple"), ("4C3275", "Apple"),
        ("4C8D79", "Apple"), ("5043AB", "Apple"), ("50EAD6", "Apple"), ("54724F", "Apple"),
        ("54AE27", "Apple"), ("5855CA", "Apple"), ("5C5948", "Apple"), ("5C8D4E", "Apple"),
        ("5C969D", "Apple"), ("5CF938", "Apple"), ("60C5AD", "Apple"), ("60D9C7", "Apple"),
        ("60F445", "Apple"), ("6437E1", "Apple"), ("64B0A6", "Apple"), ("680927", "Apple"),
        ("6C3E6D", "Apple"), ("6C94F8", "Apple"), ("70288B", "Apple"), ("703EAC", "Apple"),
        ("70CD60", "Apple"), ("74E1B6", "Apple"), ("78886D", "Apple"), ("78A3E4", "Apple"),
        ("7C5049", "Apple"), ("7CC3A1", "Apple"), ("7CD1C3", "Apple"), ("7CF05F", "Apple"),
        ("804971", "Apple"), ("807ABF", "Apple"), ("843835", "Apple"), ("84788B", "Apple"),
        ("84FCFE", "Apple"), ("8866A5", "Apple"), ("88C663", "Apple"), ("8C7C92", "Apple"),
        ("90840D", "Apple"), ("90B21F", "Apple"), ("90FD61", "Apple"), ("94E96A", "Apple"),
        ("980190", "Apple"), ("9C04EB", "Apple"), ("9C20A", "Apple"), ("9CF387", "Apple"),
        ("A01828", "Apple"), ("A45E60", "Apple"), ("A4B197", "Apple"), ("A4C361", "Apple"),
        ("A82066", "Apple"), ("A85C2C", "Apple"), ("A860B6", "Apple"), ("A8968A", "Apple"),
        ("AC293A", "Apple"), ("ACFDEC", "Apple"), ("B065BD", "Apple"), ("B0702D", "Apple"),
        ("B09FBA", "Apple"), ("B4F0AB", "Apple"), ("B8098A", "Apple"), ("B817C2", "Apple"),
        ("B844D9", "Apple"), ("B8C75D", "Apple"), ("B8E856", "Apple"), ("B8F6B1", "Apple"),
        ("BC3BAF", "Apple"), ("BC5436", "Apple"), ("BC6778", "Apple"), ("C01ADA", "Apple"),
        ("C06599", "Apple"), ("C0A53E", "Apple"), ("C0CECD", "Apple"), ("C42C03", "Apple"),
        ("C46AB7", "Apple"), ("C82A14", "Apple"), ("C86F1D", "Apple"), ("C8334B", "Apple"),
        ("CC25EF", "Apple"), ("D02B20", "Apple"), ("D03311", "Apple"), ("D0C5F3", "Apple"),
        ("D4619D", "Apple"), ("D49A20", "Apple"), ("D4A33D", "Apple"), ("D89E3F", "Apple"),
        ("DCA904", "Apple"), ("E05F45", "Apple"), ("E0B9BA", "Apple"), ("E0C767", "Apple"),
        ("E0F5C6", "Apple"), ("E4C63D", "Apple"), ("E8040B", "Apple"), ("E80688", "Apple"),
        ("E8802E", "Apple"), ("EC852F", "Apple"), ("F02475", "Apple"), ("F0B479", "Apple"),
        ("F0C1F1", "Apple"), ("F0D1A9", "Apple"), ("F0DBE2", "Apple"), ("F437B7", "Apple"),
        ("F45C89", "Apple"), ("F4F15A", "Apple"), ("F8E079", "Apple"),
        // Intel
        ("001111", "Intel"), ("001320", "Intel"), ("0013E8", "Intel"), ("001517", "Intel"),
        ("001B21", "Intel"), ("001C23", "Intel"), ("001E64", "Intel"), ("001E65", "Intel"),
        ("001F3A", "Intel"), ("001F3B", "Intel"), ("001F3C", "Intel"), ("00215C", "Intel"),
        ("00215D", "Intel"), ("002650", "Intel"), ("0026C6", "Intel"), ("0026C7", "Intel"),
        ("0C54A5", "Intel"), ("100BA9", "Intel"), ("1093E9", "Intel"), ("18FF0F", "Intel"),
        ("3413E8", "Intel"), ("34028B", "Intel"), ("3C970E", "Intel"), ("40167E", "Intel"),
        ("485AB6", "Intel"), ("48F17F", "Intel"), ("4C34BB", "Intel"), ("5440AD", "Intel"),
        ("58A839", "Intel"), ("5C5181", "Intel"), ("606720", "Intel"), ("647C34", "Intel"),
        ("68053B", "Intel"), ("68545A", "Intel"), ("685D43", "Intel"), ("74E6E2", "Intel"),
        ("78028F", "Intel"), ("78929C", "Intel"), ("7C5CF8", "Intel"), ("80C5F2", "Intel"),
        ("84A6C8", "Intel"), ("88B111", "Intel"), ("8C700B", "Intel"), ("8CA982", "Intel"),
        ("9C5C8E", "Intel"), ("9C5CF8", "Intel"), ("9CAFE4", "Intel"), ("A0510B", "Intel"),
        ("A088B4", "Intel"), ("A4C494", "Intel"), ("A860B6", "Intel"), ("B4D5BD", "Intel"),
        ("B4E1C4", "Intel"), ("B8EE65", "Intel"), ("C8F750", "Intel"), ("CC2F71", "Intel"),
        ("D0C637", "Intel"), ("D8FC93", "Intel"), ("E4B318", "Intel"), ("E8B1FC", "Intel"),
        ("F40669", "Intel"), ("F48C50", "Intel"), ("F81654", "Intel"), ("FC4596", "Intel"),
        // Samsung
        ("000FB0", "Samsung"), ("0012FB", "Samsung"), ("001632", "Samsung"), ("001AEF", "Samsung"),
        ("001DD8", "Samsung"), ("001E7D", "Samsung"), ("001FCC", "Samsung"), ("0021D1", "Samsung"),
        ("0023D7", "Samsung"), ("0024E9", "Samsung"), ("002675", "Samsung"), ("0C89DB", "Samsung"),
        ("1077B0", "Samsung"), ("107B44", "Samsung"), ("10D38A", "Samsung"), ("143E60", "Samsung"),
        ("147D05", "Samsung"), ("1816C9", "Samsung"), ("1C62B8", "Samsung"), ("205531", "Samsung"),
        ("24920E", "Samsung"), ("24C696", "Samsung"), ("286ABD", "Samsung"), ("2C4401", "Samsung"),
        ("301966", "Samsung"), ("34145F", "Samsung"), ("34BE00", "Samsung"), ("34C3AC", "Samsung"),
        ("3855ED", "Samsung"), ("3C5A37", "Samsung"), ("3C8BFE", "Samsung"), ("3CBBFD", "Samsung"),
        ("40163B", "Samsung"), ("440010", "Samsung"), ("44F437", "Samsung"), ("48137E", "Samsung"),
        ("4844F7", "Samsung"), ("4CE676", "Samsung"), ("5056BF", "Samsung"), ("5440AD", "Samsung"),
        ("54928B", "Samsung"), ("5C0A5B", "Samsung"), ("5C497D", "Samsung"), ("5C996B", "Samsung"),
        ("5CC7D7", "Samsung"), ("60AF6D", "Samsung"), ("646CB2", "Samsung"), ("68EBAE", "Samsung"),
        ("70F927", "Samsung"), ("7825AD", "Samsung"), ("787F62", "Samsung"), ("78ABBB", "Samsung"),
        ("7C0BC6", "Samsung"), ("80656D", "Samsung"), ("84119E", "Samsung"), ("848506", "Samsung"),
        ("842E27", "Samsung"), ("84C0EF", "Samsung"), ("8855F9", "Samsung"), ("88329B", "Samsung"),
        ("883F19", "Samsung"), ("8C71F8", "Samsung"), ("9003B7", "Samsung"), ("9401C2", "Samsung"),
        ("940917", "Samsung"), ("9463D1", "Samsung"), ("94B86D", "Samsung"), ("94D771", "Samsung"),
        ("983F9F", "Samsung"), ("98391C", "Samsung"), ("9852B1", "Samsung"), ("98F06A", "Samsung"),
        ("9C2A70", "Samsung"), ("9C3AAF", "Samsung"), ("A007B6", "Samsung"), ("A0CBBE", "Samsung"),
        ("A40DBC", "Samsung"), ("A4EBD3", "Samsung"), ("A82BB9", "Samsung"), ("A88195", "Samsung"),
        ("AC36B0", "Samsung"), ("AC5F3E", "Samsung"), ("ACEBDF", "Samsung"), ("B0728E", "Samsung"),
        ("B07994", "Samsung"), ("B07995", "Samsung"), ("B0DF3A", "Samsung"), ("B4EF39", "Samsung"),
        ("B82A72", "Samsung"), ("B858FC", "Samsung"), ("B8C68E", "Samsung"), ("BC1485", "Samsung"),
        ("BC20A4", "Samsung"), ("BC4760", "Samsung"), ("BC8385", "Samsung"), ("C0BDD1", "Samsung"),
        ("C4731E", "Samsung"), ("C4CBAC", "Samsung"), ("CC051B", "Samsung"), ("CC07AB", "Samsung"),
        ("CC5C75", "Samsung"), ("CCA462", "Samsung"), ("CCFE3C", "Samsung"), ("D057A1", "Samsung"),
        ("D05FB8", "Samsung"), ("D09927", "Samsung"), ("D0DFCC", "Samsung"), ("D4878F", "Samsung"),
        ("D4E8B2", "Samsung"), ("D831CF", "Samsung"), ("D87570", "Samsung"), ("DC7144", "Samsung"),
        ("E0997E", "Samsung"), ("E0DB10", "Samsung"), ("E4121D", "Samsung"), ("E4E0C5", "Samsung"),
        ("E8508B", "Samsung"), ("EC1F72", "Samsung"), ("EC3091", "Samsung"), ("ECE09B", "Samsung"),
        ("F025B7", "Samsung"), ("F0E77E", "Samsung"), ("F0EC39", "Samsung"), ("F40E11", "Samsung"),
        ("F47B5E", "Samsung"), ("F49F54", "Samsung"), ("F88E85", "Samsung"), ("FC0355", "Samsung"),
        // TP-Link
        ("002719", "TP-Link"), ("147590", "TP-Link"), ("185936", "TP-Link"), ("1C3BF3", "TP-Link"),
        ("24693E", "TP-Link"), ("3C52A1", "TP-Link"), ("30B5C2", "TP-Link"), ("50C7BF", "TP-Link"),
        ("54C80F", "TP-Link"), ("5CA6E6", "TP-Link"), ("60E327", "TP-Link"), ("6466B3", "TP-Link"),
        ("68FF7B", "TP-Link"), ("6CE873", "TP-Link"), ("742414", "TP-Link"), ("788CB5", "TP-Link"),
        ("78D294", "TP-Link"), ("802BF9", "TP-Link"), ("8416F9", "TP-Link"), ("88D7F6", "TP-Link"),
        ("8CB23E", "TP-Link"), ("94A67E", "TP-Link"), ("A842A1", "TP-Link"), ("AC84C6", "TP-Link"),
        ("B0487A", "TP-Link"), ("B4E62D", "TP-Link"), ("BC4699", "TP-Link"), ("C025E9", "TP-Link"),
        ("C46E1F", "TP-Link"), ("D46A6A", "TP-Link"), ("D80D17", "TP-Link"), ("E4D332", "TP-Link"),
        ("EC086B", "TP-Link"), ("EC172F", "TP-Link"), ("F4F26D", "TP-Link"), ("F8D111", "TP-Link"),
        // Netgear
        ("000FB5", "Netgear"), ("0024B2", "Netgear"), ("0026F2", "Netgear"), ("00146C", "Netgear"),
        ("001B2F", "Netgear"), ("001E2A", "Netgear"), ("001F33", "Netgear"), ("002275", "Netgear"),
        ("0024B2", "Netgear"), ("10C37B", "Netgear"), ("10DA43", "Netgear"), ("2030D0", "Netgear"),
        ("28C68E", "Netgear"), ("30469A", "Netgear"), ("44943C", "Netgear"), ("4C60DE", "Netgear"),
        ("6CB0CE", "Netgear"), ("802689", "Netgear"), ("84F352", "Netgear"), ("8CC7D0", "Netgear"),
        ("9CD36D", "Netgear"), ("A00460", "Netgear"), ("A021B7", "Netgear"), ("A40E2B", "Netgear"),
        ("A42B8C", "Netgear"), ("B03956", "Netgear"), ("C03F0E", "Netgear"), ("C46E1F", "Netgear"),
        ("C89E43", "Netgear"), ("CC40D0", "Netgear"), ("DC9FDB", "Netgear"), ("E0469A", "Netgear"),
        ("E091F5", "Netgear"), ("E4F4C6", "Netgear"), ("E8FCAF", "Netgear"), ("F87394", "Netgear"),
        // Cisco
        ("000142", "Cisco"), ("000143", "Cisco"), ("00016C", "Cisco"), ("00016E", "Cisco"),
        ("000196", "Cisco"), ("000197", "Cisco"), ("0001C7", "Cisco"), ("0001C9", "Cisco"),
        ("0002FC", "Cisco"), ("0002FD", "Cisco"), ("000378", "Cisco"), ("000379", "Cisco"),
        ("000469", "Cisco"), ("0005DC", "Cisco"), ("00067D", "Cisco"), ("00077D", "Cisco"),
        ("00078E", "Cisco"), ("00081A", "Cisco"), ("00090B", "Cisco"), ("000917", "Cisco"),
        ("000A41", "Cisco"), ("000A8A", "Cisco"), ("000B45", "Cisco"), ("000BE0", "Cisco"),
        ("000C30", "Cisco"), ("000C31", "Cisco"), ("000C41", "Cisco"), ("000C85", "Cisco"),
        ("000D28", "Cisco"), ("000D29", "Cisco"), ("000D65", "Cisco"), ("000E38", "Cisco"),
        ("000E83", "Cisco"), ("000E84", "Cisco"), ("000F23", "Cisco"), ("000F24", "Cisco"),
        ("001007", "Cisco"), ("0010FF", "Cisco"), ("001101", "Cisco"), ("0011BB", "Cisco"),
        ("001217", "Cisco"), ("001300", "Cisco"), ("00137F", "Cisco"), ("001411", "Cisco"),
        ("00142A", "Cisco"), ("00142B", "Cisco"), ("0014A8", "Cisco"), ("001515", "Cisco"),
        ("001560", "Cisco"), ("0015C6", "Cisco"), ("00168C", "Cisco"), ("00178B", "Cisco"),
        ("00180A", "Cisco"), ("0018B9", "Cisco"), ("0018BA", "Cisco"), ("001906", "Cisco"),
        ("00194F", "Cisco"), ("0019A9", "Cisco"), ("0019AA", "Cisco"), ("001A2F", "Cisco"),
        ("001A30", "Cisco"), ("001A6C", "Cisco"), ("001A6D", "Cisco"), ("001AC1", "Cisco"),
        ("001B0C", "Cisco"), ("001B0D", "Cisco"), ("001B2A", "Cisco"), ("001B53", "Cisco"),
        ("001B8F", "Cisco"), ("001BD4", "Cisco"), ("001BD5", "Cisco"), ("001C0E", "Cisco"),
        ("001C57", "Cisco"), ("001C58", "Cisco"), ("001CB0", "Cisco"), ("001CB1", "Cisco"),
        ("001D09", "Cisco"), ("001D45", "Cisco"), ("001D46", "Cisco"), ("001D70", "Cisco"),
        ("001D71", "Cisco"), ("001DA1", "Cisco"), ("001DA2", "Cisco"), ("001DE5", "Cisco"),
        ("001E13", "Cisco"), ("001E14", "Cisco"), ("001E49", "Cisco"), ("001E4A", "Cisco"),
        ("001E7A", "Cisco"), ("001EC9", "Cisco"), ("001EF6", "Cisco"), ("001EF7", "Cisco"),
        ("001F26", "Cisco"), ("001F27", "Cisco"), ("001F6C", "Cisco"), ("001F6D", "Cisco"),
        ("001F9D", "Cisco"), ("001F9E", "Cisco"), ("001FC9", "Cisco"), ("00209A", "Cisco"),
        ("002121", "Cisco"), ("002155", "Cisco"), ("0021A0", "Cisco"), ("0021D7", "Cisco"),
        ("00220D", "Cisco"), ("00223A", "Cisco"), ("00226B", "Cisco"), ("0022BD", "Cisco"),
        ("002355", "Cisco"), ("00238B", "Cisco"), ("0023EA", "Cisco"), ("002438", "Cisco"),
        ("002497", "Cisco"), ("0024C4", "Cisco"), ("0024F7", "Cisco"), ("0024F9", "Cisco"),
        ("002542", "Cisco"), ("002543", "Cisco"), ("0025B4", "Cisco"), ("0025B5", "Cisco"),
        ("0025CA", "Cisco"), ("002634", "Cisco"), ("002635", "Cisco"), ("00264A", "Cisco"),
        ("0026CB", "Cisco"), ("00270D", "Cisco"), ("00270E", "Cisco"), ("002738", "Cisco"),
        ("002790", "Cisco"), ("0027E3", "Cisco"), ("0030F2", "Cisco"), ("00400B", "Cisco"),
        ("004096", "Cisco"), ("00504E", "Cisco"), ("005054", "Cisco"), ("006009", "Cisco"),
        ("006070", "Cisco"), ("006456", "Cisco"), ("00900C", "Cisco"), ("00905F", "Cisco"),
        ("00906D", "Cisco"), ("009086", "Cisco"), ("0090BF", "Cisco"), ("00D006", "Cisco"),
        ("00D058", "Cisco"), ("00D079", "Cisco"), ("00E01E", "Cisco"), ("00E014", "Cisco"),
        ("00E04F", "Cisco"), ("00E034", "Cisco"), ("04C5A4", "Cisco"), ("0808C2", "Cisco"),
        ("0C1157", "Cisco"), ("0C68B4", "Cisco"), ("0C8525", "Cisco"), ("10BDC2", "Cisco"),
        ("18DB60", "Cisco"), ("18E790", "Cisco"), ("1CE6C7", "Cisco"), ("2037A5", "Cisco"),
        ("2088C2", "Cisco"), ("240E8D", "Cisco"), ("241ACA", "Cisco"), ("24376D", "Cisco"),
        ("24ECFB", "Cisco"), ("283B82", "Cisco"), ("28940F", "Cisco"), ("2C31E4", "Cisco"),
        ("2C36F8", "Cisco"), ("2C542D", "Cisco"), ("2C5496", "Cisco"), ("2C5A0F", "Cisco"),
        ("2C86D2", "Cisco"), ("3037A5", "Cisco"), ("304F1B", "Cisco"), ("30E4DB", "Cisco"),
        ("3400A3", "Cisco"), ("3490A5", "Cisco"), ("34A84E", "Cisco"), ("34BD20", "Cisco"),
        ("34DBBF", "Cisco"), ("38BF2F", "Cisco"), ("38D40B", "Cisco"), ("3C0E23", "Cisco"),
        ("4018B1", "Cisco"), ("406C8F", "Cisco"), ("40A6E8", "Cisco"), ("44ADD9", "Cisco"),
        ("44D3CA", "Cisco"), ("4C0082", "Cisco"), ("4C7E19", "Cisco"), ("4CAC0A", "Cisco"),
        ("4CE6A8", "Cisco"), ("50064F", "Cisco"), ("501CBD", "Cisco"), ("5087B8", "Cisco"),
        ("50875A", "Cisco"), ("542A1B", "Cisco"), ("546C0E", "Cisco"), ("54784F", "Cisco"),
        ("5897BD", "Cisco"), ("58973D", "Cisco"), ("5C50BA", "Cisco"), ("5C50C0", "Cisco"),
        ("5CA4F4", "Cisco"), ("6073BC", "Cisco"), ("608870", "Cisco"), ("60EDC0", "Cisco"),
        ("647E25", "Cisco"), ("64A0E7", "Cisco"), ("64D814", "Cisco"), ("64E950", "Cisco"),
        ("680715", "Cisco"), ("6886A7", "Cisco"), ("688685", "Cisco"), ("6899CD", "Cisco"),
        ("6C2056", "Cisco"), ("6C416A", "Cisco"), ("6C5E73", "Cisco"), ("70108F", "Cisco"),
        ("701F53", "Cisco"), ("70815A", "Cisco"), ("70CA9B", "Cisco"), ("70DB98", "Cisco"),
        // Ubiquiti
        ("00156D", "Ubiquiti"), ("0027D4", "Ubiquiti"), ("046E6D", "Ubiquiti"), ("0418D6", "Ubiquiti"),
        ("24A43C", "Ubiquiti"), ("44D9E7", "Ubiquiti"), ("68D79A", "Ubiquiti"), ("788A20", "Ubiquiti"),
        ("8017BB", "Ubiquiti"), ("9C05D6", "Ubiquiti"), ("AC8BA9", "Ubiquiti"), ("B4FBE4", "Ubiquiti"),
        ("DC9FDB", "Ubiquiti"), ("E063DA", "Ubiquiti"), ("F09FC2", "Ubiquiti"), ("FC6FB7", "Ubiquiti"),
        // D-Link
        ("001346", "D-Link"), ("001802", "D-Link"), ("00195B", "D-Link"), ("001CF0", "D-Link"),
        ("00219B", "D-Link"), ("00265A", "D-Link"), ("1062EB", "D-Link"), ("10BEF5", "D-Link"),
        ("14D64D", "D-Link"), ("1C7EE5", "D-Link"), ("28107B", "D-Link"), ("3CFE6A", "D-Link"),
        ("5C497D", "D-Link"), ("6400F1", "D-Link"), ("78542E", "D-Link"), ("84C9B2", "D-Link"),
        ("90942A", "D-Link"), ("941D47", "D-Link"), ("9CD643", "D-Link"), ("B8A386", "D-Link"),
        ("BC0F9A", "D-Link"), ("C8BE19", "D-Link"), ("CC1AFA", "D-Link"), ("CCB255", "D-Link"),
        // Atheros/Qualcomm
        ("00037F", "Atheros"), ("0004E2", "Atheros"), ("00083E", "Atheros"), ("000A7A", "Atheros"),
        ("001C07", "Atheros"), ("001DE0", "Atheros"), ("00223F", "Atheros"), ("0023C2", "Atheros"),
        ("0024E8", "Atheros"), ("008AD3", "Atheros"), ("14358B", "Atheros"), ("2CF7F1", "Atheros"),
        ("340027", "Atheros"), ("48F07B", "Atheros"), ("5000D3", "Atheros"), ("54E6FC", "Atheros"),
        ("649604", "Atheros"), ("6C3BE5", "Atheros"), ("781735", "Atheros"), ("88CD53", "Atheros"),
        ("90B686", "Atheros"), ("9CC9EB", "Atheros"), ("C0EED3", "Atheros"), ("C44BC1", "Atheros"),
        // Espressif (ESP32/ESP8266)
        ("10521C", "Espressif"), ("180F76", "Espressif"), ("18FE34", "Espressif"), ("240AC4", "Espressif"),
        ("2462AB", "Espressif"), ("2C3AE8", "Espressif"), ("30AEA4", "Espressif"), ("3C61A5", "Espressif"),
        ("3C71BF", "Espressif"), ("48E70A", "Espressif"), ("4C11AE", "Espressif"), ("5CCF7F", "Espressif"),
        ("68C63A", "Espressif"), ("7C9EBD", "Espressif"), ("80E7B3", "Espressif"), ("84F3EB", "Espressif"),
        ("8CAAB5", "Espressif"), ("90A0C7", "Espressif"), ("94B97E", "Espressif"), ("A020A6", "Espressif"),
        ("A4CF12", "Espressif"), ("AC67B2", "Espressif"), ("B4E62D", "Espressif"), ("BC7020", "Espressif"),
        ("C45BBE", "Espressif"), ("C4DEE2", "Espressif"), ("D8BFC0", "Espressif"), ("DC4F22", "Espressif"),
        ("E0980E", "Espressif"), ("F008D1", "Espressif"), ("F4CFA2", "Espressif"),
        // ASUSTek
        ("00248C", "ASUSTek"), ("00E018", "ASUSTek"), ("0C54A5", "ASUSTek"), ("10C37B", "ASUSTek"),
        ("14DD99", "ASUSTek"), ("1C3BF3", "ASUSTek"), ("1C872C", "ASUSTek"), ("2037A5", "ASUSTek"),
        ("2C4D54", "ASUSTek"), ("302303", "ASUSTek"), ("30F772", "ASUSTek"), ("3497F6", "ASUSTek"),
        ("38D547", "ASUSTek"), ("48E244", "ASUSTek"), ("4C30CA", "ASUSTek"), ("50465D", "ASUSTek"),
        ("50E085", "ASUSTek"), ("544A00", "ASUSTek"), ("549F35", "ASUSTek"), ("58DB15", "ASUSTek"),
        ("60A44C", "ASUSTek"), ("6045CB", "ASUSTek"), ("70F11C", "ASUSTek"), ("748D08", "ASUSTek"),
        ("789CEB", "ASUSTek"), ("7C66EF", "ASUSTek"), ("90E6BA", "ASUSTek"), ("92CF50", "ASUSTek"),
        ("985AEB", "ASUSTek"), ("A4D1D2", "ASUSTek"), ("AC220B", "ASUSTek"), ("B0C0AC", "ASUSTek"),
        ("BC0F64", "ASUSTek"), ("C86000", "ASUSTek"), ("CC9635", "ASUSTek"), ("D017C2", "ASUSTek"),
        ("D850E6", "ASUSTek"), ("E03F49", "ASUSTek"), ("F07959", "ASUSTek"), ("F46D04", "ASUSTek"),
        // Linksys
        ("001217", "Linksys"), ("001310", "Linksys"), ("00149A", "Linksys"), ("00165B", "Linksys"),
        ("00188B", "Linksys"), ("001A70", "Linksys"), ("001C10", "Linksys"), ("001D7E", "Linksys"),
        ("001EE5", "Linksys"), ("002128", "Linksys"), ("002276", "Linksys"), ("58238C", "Linksys"),
        ("5CE8CB", "Linksys"), ("68B6FC", "Linksys"), ("C43DC7", "Linksys"), ("C46AE5", "Linksys"),
        ("E8FC38", "Linksys"), ("F84F57", "Linksys"),
        // Huawei
        ("001E10", "Huawei"), ("00259E", "Huawei"), ("002ECE", "Huawei"), ("00464B", "Huawei"),
        ("049226", "Huawei"), ("0C37DC", "Huawei"), ("1070FD", "Huawei"), ("18F46A", "Huawei"),
        ("20F3A3", "Huawei"), ("246968", "Huawei"), ("284B1D", "Huawei"), ("30D17E", "Huawei"),
        ("34CDBE", "Huawei"), ("38BC01", "Huawei"), ("38E8DF", "Huawei"), ("40CB82", "Huawei"),
        ("442F6F", "Huawei"), ("4C5499", "Huawei"), ("544A16", "Huawei"), ("54A65C", "Huawei"),
        ("5C4CA9", "Huawei"), ("5CDD70", "Huawei"), ("60DE44", "Huawei"), ("64A651", "Huawei"),
        ("680571", "Huawei"), ("6CC99C", "Huawei"), ("707B3E", "Huawei"), ("70723C", "Huawei"),
        ("782BC9", "Huawei"), ("78D752", "Huawei"), ("80B686", "Huawei"), ("80FB06", "Huawei"),
        ("84DBAC", "Huawei"), ("88F031", "Huawei"), ("8C34FD", "Huawei"), ("9017AC", "Huawei"),
        ("94772B", "Huawei"), ("B0E5ED", "Huawei"), ("C8D15E", "Huawei"), ("CCF9E4", "Huawei"),
        ("D4B110", "Huawei"), ("E00EDA", "Huawei"), ("E4A8DF", "Huawei"), ("E8088B", "Huawei"),
        ("F476B5", "Huawei"), ("F4559C", "Huawei"), ("F83DFF", "Huawei"), ("FC48EF", "Huawei"),
        // Amazon (Echo, Kindle, Fire)
        ("00FC8B", "Amazon"), ("0C47C9", "Amazon"), ("18742E", "Amazon"), ("34D270", "Amazon"),
        ("40B4CD", "Amazon"), ("44650D", "Amazon"), ("50DCE7", "Amazon"), ("687D6B", "Amazon"),
        ("68DBF2", "Amazon"), ("7843C3", "Amazon"), ("74C246", "Amazon"), ("84D6D0", "Amazon"),
        ("A002DC", "Amazon"), ("AC13E7", "Amazon"), ("AC63BE", "Amazon"), ("B47C9C", "Amazon"),
        ("F0272D", "Amazon"), ("F8AB05", "Amazon"), ("FC6519", "Amazon"), ("FCFC48", "Amazon"),
        // Google (Nest, Chromecast)
        ("00F861", "Google"), ("1C7E58", "Google"), ("20DF5F", "Google"), ("24E314", "Google"),
        ("3CF731", "Google"), ("54605C", "Google"), ("6C0B84", "Google"), ("94EB2C", "Google"),
        ("A47733", "Google"), ("B47F5B", "Google"), ("D89695", "Google"), ("DC56E7", "Google"),
        ("F47F35", "Google"), ("F88FCA", "Google"), ("FA8F00", "Google"),
        // Sonos
        ("000E58", "Sonos"), ("00173F", "Sonos"), ("485D36", "Sonos"), ("5CAAFD", "Sonos"),
        ("7828CA", "Sonos"), ("7C0526", "Sonos"), ("949F3E", "Sonos"), ("9C1E95", "Sonos"),
        ("B8E937", "Sonos"), ("C438F1", "Sonos"), ("E43EC6", "Sonos"),
        // Miscellaneous IoT
        ("18FE34", "Espressif"), ("3C71BF", "Espressif"), ("ACDE48", "Raspberry Pi"),
        ("B827EB", "Raspberry Pi"), ("DC:A6:32", "Raspberry Pi"), ("E45F01", "Raspberry Pi"),
    ];

    let manufacturers = OUI_DATABASE;

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

/// Parse radiotap header and extract 802.11 frame
fn parse_radiotap_and_80211(data: &[u8]) -> Option<Frame80211> {
    // Radiotap header format:
    // - Version (1 byte): 0
    // - Pad (1 byte)
    // - Length (2 bytes, little-endian)
    // - Present flags (4 bytes)
    // - Fields based on present flags
    if data.len() < 8 {
        return None;
    }

    // Check radiotap version
    if data[0] != 0 {
        return None;
    }

    // Get radiotap length
    let radiotap_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    if data.len() < radiotap_len + 24 {
        // Minimum 802.11 header is 24 bytes
        return None;
    }

    // Parse radiotap fields to extract signal strength and channel
    let (signal_dbm, channel) = parse_radiotap_fields(&data[..radiotap_len]);

    // Parse 802.11 frame header (after radiotap)
    let frame_data = &data[radiotap_len..];
    parse_80211_frame(frame_data, signal_dbm, channel)
}

/// Parse radiotap header fields to extract signal strength and channel
fn parse_radiotap_fields(data: &[u8]) -> (Option<i8>, Option<u8>) {
    if data.len() < 8 {
        return (None, None);
    }

    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut offset = 8;
    let mut signal_dbm = None;
    let mut channel = None;

    // Radiotap present flags (IEEE 802.11 radiotap):
    // Bit 0: TSFT (8 bytes)
    // Bit 1: Flags (1 byte)
    // Bit 2: Rate (1 byte)
    // Bit 3: Channel (4 bytes: 2 freq + 2 flags)
    // Bit 4: FHSS (2 bytes)
    // Bit 5: Antenna signal dBm (1 byte)
    // Bit 6: Antenna noise dBm (1 byte)

    // Process fields in order based on present bits
    if present & (1 << 0) != 0 {
        // TSFT - 8 bytes, 8-byte aligned
        offset = (offset + 7) & !7;
        offset += 8;
    }
    if present & (1 << 1) != 0 && offset < data.len() {
        // Flags - 1 byte
        offset += 1;
    }
    if present & (1 << 2) != 0 && offset < data.len() {
        // Rate - 1 byte
        offset += 1;
    }
    if present & (1 << 3) != 0 {
        // Channel - 4 bytes, 2-byte aligned
        offset = (offset + 1) & !1;
        if offset + 4 <= data.len() {
            let freq = u16::from_le_bytes([data[offset], data[offset + 1]]);
            channel = frequency_to_channel(freq as u32);
            offset += 4;
        }
    }
    if present & (1 << 4) != 0 && offset + 2 <= data.len() {
        // FHSS - 2 bytes
        offset += 2;
    }
    if present & (1 << 5) != 0 && offset < data.len() {
        // Antenna signal dBm - 1 byte (signed)
        signal_dbm = Some(data[offset] as i8);
        // offset += 1;
    }

    (signal_dbm, channel)
}

/// Parse 802.11 frame header
fn parse_80211_frame(data: &[u8], signal_dbm: Option<i8>, channel: Option<u8>) -> Option<Frame80211> {
    if data.len() < 24 {
        return None;
    }

    // Frame control field (2 bytes)
    let fc = u16::from_le_bytes([data[0], data[1]]);
    let frame_type = ((fc >> 2) & 0x03) as u8;
    let subtype = ((fc >> 4) & 0x0F) as u8;
    let to_ds = (data[1] & ieee80211::FC_TO_DS) != 0;
    let from_ds = (data[1] & ieee80211::FC_FROM_DS) != 0;

    // Duration (2 bytes) - skipped
    // let duration = u16::from_le_bytes([data[2], data[3]]);

    // Addresses (6 bytes each)
    let mut addr1 = [0u8; 6];
    let mut addr2 = [0u8; 6];
    let mut addr3 = [0u8; 6];
    addr1.copy_from_slice(&data[4..10]);
    addr2.copy_from_slice(&data[10..16]);
    addr3.copy_from_slice(&data[16..22]);

    // Sequence control (2 bytes)
    let seq_ctrl = u16::from_le_bytes([data[22], data[23]]);

    // Check for Address 4 (WDS mode: both ToDS and FromDS set)
    let (addr4, body_offset) = if to_ds && from_ds && data.len() >= 30 {
        let mut a4 = [0u8; 6];
        a4.copy_from_slice(&data[24..30]);
        (Some(a4), 30)
    } else {
        (None, 24)
    };

    // For QoS data frames, there's a 2-byte QoS control field
    let body_start = if frame_type == ieee80211::TYPE_DATA && (subtype & 0x08) != 0 {
        body_offset + 2
    } else {
        body_offset
    };

    let body = if body_start < data.len() {
        data[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Some(Frame80211 {
        frame_type,
        subtype,
        to_ds,
        from_ds,
        addr1,
        addr2,
        addr3,
        addr4,
        seq_ctrl,
        body,
        signal_dbm,
        channel,
    })
}

/// Handle management frames (beacons, probes, etc.)
fn handle_management_frame(
    frame: &Frame80211,
    access_points: &Arc<Mutex<HashMap<String, AccessPoint>>>,
    clients: &Arc<Mutex<HashMap<String, WirelessClient>>>,
    config: &WirelessScanConfig,
) {
    let signal = frame.signal_dbm.unwrap_or(-80);
    let channel = frame.channel.unwrap_or(0);

    match frame.subtype {
        ieee80211::SUBTYPE_BEACON | ieee80211::SUBTYPE_PROBE_RESP => {
            // Beacon or Probe Response from AP
            let bssid = format_mac(&frame.addr2);

            // Parse information elements from frame body
            // Fixed parameters: timestamp (8), beacon interval (2), capability (2)
            if frame.body.len() < 12 {
                return;
            }

            let ies = parse_ie(&frame.body[12..]);
            let mut ssid: Option<String> = None;
            let mut security_info = SecurityInfo::default();

            for ie in &ies {
                match ie.id {
                    ie_ids::SSID => {
                        if !ie.data.is_empty() {
                            if let Ok(s) = std::str::from_utf8(&ie.data) {
                                if !s.chars().all(|c| c == '\0') {
                                    ssid = Some(s.to_string());
                                }
                            }
                        }
                    }
                    ie_ids::DS_PARAMETER => {
                        // Channel from DS Parameter Set
                        // Already have from radiotap, but can use as fallback
                    }
                    ie_ids::RSN => {
                        // WPA2/WPA3 RSN IE
                        if let Ok(info) = parse_rsn_ie(&ie.data) {
                            security_info = info;
                        }
                    }
                    ie_ids::VENDOR_SPECIFIC => {
                        // Check for WPA IE (Microsoft OUI)
                        if ie.data.len() >= 4 && &ie.data[0..3] == [0x00, 0x50, 0xF2] {
                            if ie.data[3] == 1 {
                                // WPA IE
                                if let Ok(info) = parse_wpa_ie(&ie.data) {
                                    // Merge with existing if WPA2 was also found
                                    if security_info.wpa_versions.is_empty() {
                                        security_info = info;
                                    } else {
                                        security_info.wpa_versions.extend(info.wpa_versions);
                                        security_info.security_type = SecurityType::WpaWpa2Mixed;
                                    }
                                }
                            } else if ie.data[3] == 4 {
                                // WPS IE
                                security_info.wps_enabled = true;
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Apply SSID filter if configured
            if let Some(ref filter_ssid) = config.ssid_filter {
                if let Some(ref net_ssid) = ssid {
                    if !net_ssid.eq_ignore_ascii_case(filter_ssid) {
                        return;
                    }
                } else {
                    return;
                }
            }

            // Update access point record
            let mut aps = access_points.lock().unwrap();
            let now = chrono::Utc::now();

            let ap = aps.entry(bssid.clone()).or_insert_with(|| {
                AccessPoint {
                    bssid: bssid.clone(),
                    ssid: ssid.clone(),
                    hidden: ssid.is_none() || ssid.as_ref().map(|s| s.is_empty()).unwrap_or(true),
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
                    manufacturer: get_manufacturer(&bssid),
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
                ap.ssid = ssid;
                ap.hidden = false;
            }
        }

        ieee80211::SUBTYPE_PROBE_REQ => {
            // Probe request from client
            let client_mac = format_mac(&frame.addr2);

            // Parse SSID from probe request body
            let ies = parse_ie(&frame.body);
            let ssid = ies.iter()
                .find(|ie| ie.id == ie_ids::SSID)
                .and_then(|ie| {
                    if !ie.data.is_empty() {
                        std::str::from_utf8(&ie.data).ok().map(|s| s.to_string())
                    } else {
                        None
                    }
                });

            // Update client record
            let mut cls = clients.lock().unwrap();
            let now = chrono::Utc::now();

            let client = cls.entry(client_mac.clone()).or_insert_with(|| {
                WirelessClient {
                    mac_address: client_mac.clone(),
                    associated_bssid: None,
                    signal_dbm: signal,
                    manufacturer: get_manufacturer(&client_mac),
                    probes: Vec::new(),
                    first_seen: now,
                    last_seen: now,
                    data_count: 0,
                }
            });

            client.last_seen = now;
            client.signal_dbm = signal;

            if let Some(ref s) = ssid {
                if !s.is_empty() && !client.probes.contains(s) {
                    client.probes.push(s.clone());
                }
            }
        }

        ieee80211::SUBTYPE_ASSOC_REQ | ieee80211::SUBTYPE_REASSOC_REQ => {
            // Client associating with AP
            let client_mac = format_mac(&frame.addr2);
            let bssid = format_mac(&frame.addr1);

            let mut cls = clients.lock().unwrap();
            let now = chrono::Utc::now();

            let client = cls.entry(client_mac.clone()).or_insert_with(|| {
                WirelessClient {
                    mac_address: client_mac.clone(),
                    associated_bssid: Some(bssid.clone()),
                    signal_dbm: signal,
                    manufacturer: get_manufacturer(&client_mac),
                    probes: Vec::new(),
                    first_seen: now,
                    last_seen: now,
                    data_count: 0,
                }
            });

            client.associated_bssid = Some(bssid);
            client.last_seen = now;
        }

        ieee80211::SUBTYPE_DEAUTH | ieee80211::SUBTYPE_DISASSOC => {
            // Deauthentication or disassociation
            // Could indicate attack or client leaving network
            log::debug!("Deauth/Disassoc detected: {} -> {}",
                       format_mac(&frame.addr2), format_mac(&frame.addr1));
        }

        _ => {}
    }
}

/// Handle data frames (including EAPOL handshakes)
fn handle_data_frame(
    frame: &Frame80211,
    access_points: &Arc<Mutex<HashMap<String, AccessPoint>>>,
    clients: &Arc<Mutex<HashMap<String, WirelessClient>>>,
    handshakes: &Arc<Mutex<Vec<CapturedHandshake>>>,
    pmkids: &Arc<Mutex<Vec<PmkidData>>>,
    config: &WirelessScanConfig,
) {
    let signal = frame.signal_dbm.unwrap_or(-80);
    let bssid = format_mac(&frame.get_bssid());
    let src = format_mac(&frame.get_src());
    let dst = format_mac(&frame.get_dst());

    // Update client data count
    {
        let mut cls = clients.lock().unwrap();
        if let Some(client) = cls.get_mut(&src) {
            client.data_count += 1;
            client.last_seen = chrono::Utc::now();
            client.signal_dbm = signal;
        }
    }

    // Update AP data count
    {
        let mut aps = access_points.lock().unwrap();
        if let Some(ap) = aps.get_mut(&bssid) {
            ap.data_count += 1;
            ap.last_seen = chrono::Utc::now();
        }
    }

    // Check for EAPOL frames
    if config.capture_handshakes && frame.body.len() >= 10 {
        // LLC/SNAP header check for EAPOL
        // LLC: 0xAA 0xAA 0x03 (SNAP)
        // OUI: 0x00 0x00 0x00
        // Type: 0x88 0x8E (EAPOL)
        if frame.body.len() >= 8 &&
           frame.body[0..3] == [0xAA, 0xAA, 0x03] &&
           frame.body[3..6] == [0x00, 0x00, 0x00] {
            let ethertype = u16::from_be_bytes([frame.body[6], frame.body[7]]);

            if ethertype == ieee80211::ETHERTYPE_EAPOL {
                let eapol_data = &frame.body[8..];
                if let Some(eapol_msg) = parse_eapol_key(eapol_data) {
                    // Get SSID from AP if known
                    let ssid = {
                        let aps = access_points.lock().unwrap();
                        aps.get(&bssid)
                            .and_then(|ap| ap.ssid.clone())
                            .unwrap_or_default()
                    };

                    // Determine client MAC (the one that's not the BSSID)
                    let client_mac = if src == bssid { dst.clone() } else { src.clone() };

                    // Check for PMKID in message 1
                    if config.capture_pmkid && eapol_msg.message_number == 1 {
                        if let Some(pmkid) = extract_pmkid_from_key_data(&eapol_msg.key_data) {
                            let mut pmkid_list = pmkids.lock().unwrap();
                            let exists = pmkid_list.iter().any(|p| p.pmkid == pmkid);
                            if !exists {
                                pmkid_list.push(PmkidData {
                                    pmkid,
                                    bssid: bssid.clone(),
                                    client_mac: client_mac.clone(),
                                    ssid: ssid.clone(),
                                    captured_at: chrono::Utc::now(),
                                });
                                log::info!("Captured PMKID for {} ({})", ssid, bssid);
                            }
                        }
                    }

                    // Update handshake collection
                    let mut hs_list = handshakes.lock().unwrap();

                    // Find or create handshake entry
                    let existing_idx = hs_list.iter()
                        .position(|h| h.bssid == bssid && h.client_mac == client_mac);

                    let hs_idx = match existing_idx {
                        Some(idx) => idx,
                        None => {
                            hs_list.push(CapturedHandshake {
                                bssid: bssid.clone(),
                                ssid: ssid.clone(),
                                client_mac: client_mac.clone(),
                                anonce: Vec::new(),
                                snonce: Vec::new(),
                                message1: None,
                                message2: None,
                                message3: None,
                                message4: None,
                                complete: false,
                                captured_at: chrono::Utc::now(),
                            });
                            hs_list.len() - 1
                        }
                    };

                    if let Some(hs) = hs_list.get_mut(hs_idx) {
                        match eapol_msg.message_number {
                            1 => {
                                hs.anonce = eapol_msg.nonce.clone();
                                hs.message1 = Some(eapol_msg);
                            }
                            2 => {
                                hs.snonce = eapol_msg.nonce.clone();
                                hs.message2 = Some(eapol_msg);
                            }
                            3 => {
                                hs.message3 = Some(eapol_msg);
                            }
                            4 => {
                                hs.message4 = Some(eapol_msg);
                            }
                            _ => {}
                        }

                        let was_complete = hs.complete;
                        hs.complete = hs.is_crackable();

                        if !was_complete && hs.complete {
                            log::info!("Captured complete handshake for {} ({})",
                                      hs.ssid, hs.bssid);
                        }
                    }
                }
            }
        }
    }
}

/// Parse EAPOL-Key message
fn parse_eapol_key(data: &[u8]) -> Option<EapolMessage> {
    // EAPOL header: version (1), type (1), length (2)
    // Key descriptor: type (1), key info (2), key len (2), replay (8),
    //                 nonce (32), iv (16), rsc (8), id (8), mic (16), key_data_len (2), key_data
    if data.len() < 99 {
        return None;
    }

    // Check EAPOL type (3 = Key)
    if data[1] != 3 {
        return None;
    }

    // Key descriptor type (1 = RC4, 2 = HMAC-SHA1-AES)
    let key_type = data[4];
    if key_type != 1 && key_type != 2 && key_type != 254 {
        return None;
    }

    let key_info = u16::from_be_bytes([data[5], data[6]]);
    let key_length = u16::from_be_bytes([data[7], data[8]]);
    let replay_counter = u64::from_be_bytes([
        data[9], data[10], data[11], data[12],
        data[13], data[14], data[15], data[16],
    ]);

    let mut nonce = vec![0u8; 32];
    nonce.copy_from_slice(&data[17..49]);

    let mut key_iv = vec![0u8; 16];
    key_iv.copy_from_slice(&data[49..65]);

    let mut key_rsc = vec![0u8; 8];
    key_rsc.copy_from_slice(&data[65..73]);

    // Skip Key ID (8 bytes at 73-81)

    let mut mic = vec![0u8; 16];
    mic.copy_from_slice(&data[81..97]);

    let key_data_len = u16::from_be_bytes([data[97], data[98]]) as usize;
    let key_data = if data.len() >= 99 + key_data_len {
        data[99..99 + key_data_len].to_vec()
    } else {
        Vec::new()
    };

    // Determine message number from key info flags
    // Bit 3: Install (set in M3)
    // Bit 6: ACK (set in M1, M3)
    // Bit 8: MIC (set in M2, M3, M4)
    let ack = (key_info & 0x0080) != 0;
    let mic_flag = (key_info & 0x0100) != 0;
    let install = (key_info & 0x0040) != 0;
    let secure = (key_info & 0x0200) != 0;

    let message_number = if ack && !mic_flag {
        1 // M1: ACK set, MIC not set
    } else if !ack && mic_flag && !install && !secure {
        2 // M2: MIC set, no ACK, no Install
    } else if ack && mic_flag && install {
        3 // M3: ACK, MIC, Install set
    } else if !ack && mic_flag && secure {
        4 // M4: MIC and Secure set, no ACK
    } else {
        0 // Unknown
    };

    Some(EapolMessage {
        message_number,
        key_type,
        key_info,
        key_length,
        replay_counter,
        nonce,
        key_iv,
        key_rsc,
        mic,
        key_data,
        raw_data: data.to_vec(),
    })
}

/// Extract PMKID from EAPOL M1 key data
fn extract_pmkid_from_key_data(key_data: &[u8]) -> Option<Vec<u8>> {
    // PMKID is in an RSN IE within the key data
    // Format: Tag (1), Length (1), OUI (3), OUI Type (1), PMKID List Count (2), PMKIDs (16 each)
    let mut pos = 0;

    while pos + 2 < key_data.len() {
        let tag = key_data[pos];
        let len = key_data[pos + 1] as usize;

        if pos + 2 + len > key_data.len() {
            break;
        }

        // Look for PMKID KDE (type 4)
        // Format: 0xDD, length, OUI (00:0F:AC), type (4), PMKID
        if tag == 0xDD && len >= 20 {
            let kde_data = &key_data[pos + 2..pos + 2 + len];
            if kde_data.len() >= 20 &&
               kde_data[0..3] == [0x00, 0x0F, 0xAC] &&
               kde_data[3] == 4 {
                // Found PMKID KDE
                return Some(kde_data[4..20].to_vec());
            }
        }

        pos += 2 + len;
    }

    None
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
