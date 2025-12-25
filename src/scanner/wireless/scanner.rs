//! Wireless Network Scanner
//!
//! Discovers wireless networks and clients using aircrack-ng suite tools.

use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;
use chrono::Utc;
use anyhow::{Result, Context};
use regex::Regex;

use super::types::*;

/// Wireless scanner for network discovery
pub struct WirelessScanner {
    interface: String,
}

impl WirelessScanner {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    /// List all wireless interfaces on the system
    pub async fn list_interfaces() -> Result<Vec<WirelessInterface>> {
        let mut interfaces = Vec::new();

        // Use iw to list wireless devices
        let output = Command::new("iw")
            .args(["dev"])
            .output()
            .await
            .context("Failed to run iw dev")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_interface: Option<WirelessInterface> = None;

        for line in stdout.lines() {
            let line = line.trim();

            if line.starts_with("Interface ") {
                // Save previous interface if any
                if let Some(iface) = current_interface.take() {
                    interfaces.push(iface);
                }

                let name = line.strip_prefix("Interface ").unwrap_or("").to_string();
                current_interface = Some(WirelessInterface {
                    name,
                    mac_address: String::new(),
                    driver: String::new(),
                    chipset: None,
                    monitor_mode_supported: false,
                    current_mode: "managed".to_string(),
                    channel: None,
                    frequency: None,
                });
            } else if let Some(ref mut iface) = current_interface {
                if line.starts_with("addr ") {
                    iface.mac_address = line.strip_prefix("addr ").unwrap_or("").to_string();
                } else if line.starts_with("type ") {
                    iface.current_mode = line.strip_prefix("type ").unwrap_or("managed").to_string();
                } else if line.starts_with("channel ") {
                    if let Some(ch_str) = line.strip_prefix("channel ") {
                        if let Some(ch) = ch_str.split_whitespace().next() {
                            iface.channel = ch.parse().ok();
                        }
                    }
                }
            }
        }

        // Don't forget the last interface
        if let Some(iface) = current_interface {
            interfaces.push(iface);
        }

        // Check monitor mode support using airmon-ng
        for iface in &mut interfaces {
            iface.monitor_mode_supported = Self::check_monitor_mode_support(&iface.name).await;

            // Get driver info
            if let Ok((driver, chipset)) = Self::get_driver_info(&iface.name).await {
                iface.driver = driver;
                iface.chipset = chipset;
            }
        }

        Ok(interfaces)
    }

    /// Check if an interface supports monitor mode
    async fn check_monitor_mode_support(interface: &str) -> bool {
        // Check using iw phy info
        let output = Command::new("iw")
            .args(["phy"])
            .output()
            .await;

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Look for monitor mode in supported modes
            stdout.contains("* monitor")
        } else {
            false
        }
    }

    /// Get driver and chipset information
    async fn get_driver_info(interface: &str) -> Result<(String, Option<String>)> {
        let driver_path = format!("/sys/class/net/{}/device/driver", interface);

        // Read driver from sysfs
        let driver = if let Ok(link) = tokio::fs::read_link(&driver_path).await {
            link.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            "unknown".to_string()
        };

        // Try to get chipset from lspci/lsusb
        let chipset = None; // Would need more complex parsing

        Ok((driver, chipset))
    }

    /// Enable monitor mode on interface
    pub async fn enable_monitor_mode(interface: &str) -> Result<String> {
        // First, bring the interface down
        Command::new("ip")
            .args(["link", "set", interface, "down"])
            .output()
            .await
            .context("Failed to bring interface down")?;

        // Set monitor mode using iw
        let output = Command::new("iw")
            .args([interface, "set", "monitor", "control"])
            .output()
            .await
            .context("Failed to set monitor mode")?;

        if !output.status.success() {
            // Try using airmon-ng as fallback
            let output = Command::new("airmon-ng")
                .args(["start", interface])
                .output()
                .await
                .context("Failed to start airmon-ng")?;

            if !output.status.success() {
                anyhow::bail!("Failed to enable monitor mode: {}",
                    String::from_utf8_lossy(&output.stderr));
            }

            // airmon-ng might create a new interface (e.g., wlan0mon)
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(mon_iface) = Self::parse_monitor_interface(&stdout) {
                return Ok(mon_iface);
            }
        }

        // Bring the interface back up
        Command::new("ip")
            .args(["link", "set", interface, "up"])
            .output()
            .await
            .context("Failed to bring interface up")?;

        Ok(interface.to_string())
    }

    /// Parse monitor interface name from airmon-ng output
    fn parse_monitor_interface(output: &str) -> Option<String> {
        // Look for patterns like "wlan0mon" or "(monitor mode enabled on mon0)"
        let re = Regex::new(r"(?:monitor mode (?:enabled|vif enabled) on |created )(\w+)").ok()?;
        re.captures(output)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    /// Disable monitor mode
    pub async fn disable_monitor_mode(interface: &str) -> Result<()> {
        // Try airmon-ng stop first
        let output = Command::new("airmon-ng")
            .args(["stop", interface])
            .output()
            .await;

        if output.is_err() || !output.unwrap().status.success() {
            // Fallback to manual method
            Command::new("ip")
                .args(["link", "set", interface, "down"])
                .output()
                .await?;

            Command::new("iw")
                .args([interface, "set", "type", "managed"])
                .output()
                .await?;

            Command::new("ip")
                .args(["link", "set", interface, "up"])
                .output()
                .await?;
        }

        Ok(())
    }

    /// Set interface channel
    pub async fn set_channel(&self, channel: u8) -> Result<()> {
        let output = Command::new("iw")
            .args(["dev", &self.interface, "set", "channel", &channel.to_string()])
            .output()
            .await
            .context("Failed to set channel")?;

        if !output.status.success() {
            anyhow::bail!("Failed to set channel: {}",
                String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    /// Scan for wireless networks using airodump-ng
    pub async fn scan_networks(&self, duration_secs: u32) -> Result<Vec<WirelessNetwork>> {
        let temp_file = format!("/tmp/heroforge_scan_{}", uuid::Uuid::new_v4());

        // Start airodump-ng
        let mut child = Command::new("airodump-ng")
            .args([
                "--write", &temp_file,
                "--output-format", "csv",
                "--write-interval", "1",
                &self.interface,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to start airodump-ng")?;

        // Wait for specified duration
        tokio::time::sleep(tokio::time::Duration::from_secs(duration_secs as u64)).await;

        // Kill airodump-ng
        child.kill().await.ok();

        // Parse the CSV output
        let csv_file = format!("{}-01.csv", temp_file);
        let networks = Self::parse_airodump_csv(&csv_file).await?;

        // Cleanup temp files
        let _ = tokio::fs::remove_file(&csv_file).await;
        let _ = tokio::fs::remove_file(format!("{}-01.kismet.csv", temp_file)).await;
        let _ = tokio::fs::remove_file(format!("{}-01.kismet.netxml", temp_file)).await;
        let _ = tokio::fs::remove_file(format!("{}-01.cap", temp_file)).await;

        Ok(networks)
    }

    /// Parse airodump-ng CSV output
    async fn parse_airodump_csv(file_path: &str) -> Result<Vec<WirelessNetwork>> {
        let content = tokio::fs::read_to_string(file_path)
            .await
            .context("Failed to read airodump CSV")?;

        let mut networks = Vec::new();
        let mut clients: HashMap<String, Vec<WirelessClient>> = HashMap::new();
        let mut in_station_section = false;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            if line.starts_with("Station MAC") {
                in_station_section = true;
                continue;
            }

            if line.starts_with("BSSID") {
                in_station_section = false;
                continue;
            }

            let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

            if in_station_section {
                // Parse station/client
                if fields.len() >= 6 {
                    let client_mac = fields[0].to_string();
                    let associated_bssid = if fields[5].is_empty() || fields[5] == "(not associated)" {
                        None
                    } else {
                        Some(fields[5].to_string())
                    };

                    let client = WirelessClient {
                        mac_address: client_mac,
                        associated_bssid: associated_bssid.clone(),
                        signal_strength: fields.get(3).and_then(|s| s.parse().ok()).unwrap_or(-100),
                        packets: fields.get(4).and_then(|s| s.parse().ok()).unwrap_or(0),
                        probes: fields.get(6).map(|s| {
                            s.split(',').map(|p| p.trim().to_string()).collect()
                        }).unwrap_or_default(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                    };

                    if let Some(bssid) = associated_bssid {
                        clients.entry(bssid).or_default().push(client);
                    }
                }
            } else {
                // Parse access point
                if fields.len() >= 14 {
                    let bssid = fields[0].to_string();
                    if bssid.is_empty() || !bssid.contains(':') {
                        continue;
                    }

                    let encryption = Self::parse_encryption(fields.get(5).unwrap_or(&""));
                    let cipher = Self::parse_cipher(fields.get(6).unwrap_or(&""));
                    let auth = Self::parse_auth(fields.get(7).unwrap_or(&""));

                    let network = WirelessNetwork {
                        bssid: bssid.clone(),
                        ssid: fields.get(13).unwrap_or(&"").to_string(),
                        channel: fields.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                        frequency: Self::channel_to_freq(
                            fields.get(3).and_then(|s| s.parse().ok()).unwrap_or(0)
                        ),
                        signal_strength: fields.get(8).and_then(|s| s.parse().ok()).unwrap_or(-100),
                        encryption,
                        cipher,
                        auth,
                        wps_enabled: false, // Would need separate WPS scan
                        wps_locked: false,
                        clients: clients.remove(&bssid).unwrap_or_default(),
                        beacons: fields.get(9).and_then(|s| s.parse().ok()).unwrap_or(0),
                        data_packets: fields.get(10).and_then(|s| s.parse().ok()).unwrap_or(0),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                    };

                    networks.push(network);
                }
            }
        }

        Ok(networks)
    }

    /// Parse encryption type from airodump output
    fn parse_encryption(enc: &str) -> WirelessEncryption {
        let enc = enc.to_uppercase();
        if enc.contains("WPA3") {
            WirelessEncryption::Wpa3
        } else if enc.contains("WPA2") {
            if enc.contains("MGT") || enc.contains("EAP") {
                WirelessEncryption::Wpa2Enterprise
            } else {
                WirelessEncryption::Wpa2
            }
        } else if enc.contains("WPA") {
            if enc.contains("MGT") || enc.contains("EAP") {
                WirelessEncryption::WpaEnterprise
            } else {
                WirelessEncryption::Wpa
            }
        } else if enc.contains("WEP") {
            WirelessEncryption::Wep
        } else if enc.contains("OPN") || enc.is_empty() {
            WirelessEncryption::Open
        } else {
            WirelessEncryption::Unknown
        }
    }

    /// Parse cipher suite
    fn parse_cipher(cipher: &str) -> Option<CipherSuite> {
        let cipher = cipher.to_uppercase();
        if cipher.contains("CCMP") {
            Some(CipherSuite::Ccmp)
        } else if cipher.contains("TKIP") {
            Some(CipherSuite::Tkip)
        } else if cipher.contains("WEP") {
            Some(CipherSuite::Wep40)
        } else {
            None
        }
    }

    /// Parse authentication type
    fn parse_auth(auth: &str) -> Option<AuthType> {
        let auth = auth.to_uppercase();
        if auth.contains("PSK") {
            Some(AuthType::Psk)
        } else if auth.contains("MGT") || auth.contains("EAP") {
            Some(AuthType::Eap)
        } else if auth.contains("SAE") {
            Some(AuthType::Sae)
        } else if auth.contains("OPN") {
            Some(AuthType::Open)
        } else {
            None
        }
    }

    /// Convert WiFi channel to frequency
    fn channel_to_freq(channel: u8) -> u32 {
        match channel {
            1 => 2412,
            2 => 2417,
            3 => 2422,
            4 => 2427,
            5 => 2432,
            6 => 2437,
            7 => 2442,
            8 => 2447,
            9 => 2452,
            10 => 2457,
            11 => 2462,
            12 => 2467,
            13 => 2472,
            14 => 2484,
            // 5GHz channels
            36 => 5180,
            40 => 5200,
            44 => 5220,
            48 => 5240,
            52 => 5260,
            56 => 5280,
            60 => 5300,
            64 => 5320,
            100 => 5500,
            104 => 5520,
            108 => 5540,
            112 => 5560,
            116 => 5580,
            120 => 5600,
            124 => 5620,
            128 => 5640,
            132 => 5660,
            136 => 5680,
            140 => 5700,
            144 => 5720,
            149 => 5745,
            153 => 5765,
            157 => 5785,
            161 => 5805,
            165 => 5825,
            _ => 0,
        }
    }

    /// Quick scan using iwlist (doesn't require monitor mode)
    pub async fn quick_scan(interface: &str) -> Result<Vec<WirelessNetwork>> {
        let output = Command::new("iwlist")
            .args([interface, "scan"])
            .output()
            .await
            .context("Failed to run iwlist scan")?;

        if !output.status.success() {
            anyhow::bail!("iwlist scan failed: {}",
                String::from_utf8_lossy(&output.stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_iwlist_output(&stdout)
    }

    /// Parse iwlist scan output
    fn parse_iwlist_output(output: &str) -> Result<Vec<WirelessNetwork>> {
        let mut networks = Vec::new();
        let mut current: Option<WirelessNetwork> = None;

        for line in output.lines() {
            let line = line.trim();

            if line.contains("Cell ") && line.contains("Address:") {
                // Save previous network
                if let Some(net) = current.take() {
                    networks.push(net);
                }

                // Start new network
                let bssid = line.split("Address:").nth(1)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();

                current = Some(WirelessNetwork {
                    bssid,
                    ssid: String::new(),
                    channel: 0,
                    frequency: 0,
                    signal_strength: -100,
                    encryption: WirelessEncryption::Open,
                    cipher: None,
                    auth: None,
                    wps_enabled: false,
                    wps_locked: false,
                    clients: Vec::new(),
                    beacons: 0,
                    data_packets: 0,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                });
            } else if let Some(ref mut net) = current {
                if line.starts_with("ESSID:") {
                    net.ssid = line.strip_prefix("ESSID:")
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"')
                        .to_string();
                } else if line.starts_with("Channel:") {
                    if let Some(ch) = line.strip_prefix("Channel:") {
                        net.channel = ch.trim().parse().unwrap_or(0);
                        net.frequency = Self::channel_to_freq(net.channel);
                    }
                } else if line.starts_with("Frequency:") {
                    // Parse frequency like "Frequency:2.437 GHz (Channel 6)"
                    if let Some(freq_str) = line.split_whitespace().nth(0) {
                        if let Some(freq) = freq_str.strip_prefix("Frequency:") {
                            if let Ok(f) = freq.parse::<f64>() {
                                net.frequency = (f * 1000.0) as u32;
                            }
                        }
                    }
                } else if line.contains("Signal level=") {
                    // Parse signal like "Signal level=-65 dBm"
                    if let Some(sig) = line.split("Signal level=").nth(1) {
                        let sig = sig.split_whitespace().next().unwrap_or("-100");
                        net.signal_strength = sig.parse().unwrap_or(-100);
                    }
                } else if line.contains("Encryption key:on") {
                    net.encryption = WirelessEncryption::Unknown; // Will be refined below
                } else if line.contains("WPA2") {
                    net.encryption = WirelessEncryption::Wpa2;
                } else if line.contains("WPA") && !line.contains("WPA2") {
                    net.encryption = WirelessEncryption::Wpa;
                } else if line.contains("CCMP") {
                    net.cipher = Some(CipherSuite::Ccmp);
                } else if line.contains("TKIP") {
                    net.cipher = Some(CipherSuite::Tkip);
                } else if line.contains("PSK") {
                    net.auth = Some(AuthType::Psk);
                }
            }
        }

        // Don't forget the last network
        if let Some(net) = current {
            networks.push(net);
        }

        Ok(networks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_encryption() {
        assert_eq!(
            WirelessScanner::parse_encryption("WPA2"),
            WirelessEncryption::Wpa2
        );
        assert_eq!(
            WirelessScanner::parse_encryption("WPA"),
            WirelessEncryption::Wpa
        );
        assert_eq!(
            WirelessScanner::parse_encryption("OPN"),
            WirelessEncryption::Open
        );
    }

    #[test]
    fn test_channel_to_freq() {
        assert_eq!(WirelessScanner::channel_to_freq(1), 2412);
        assert_eq!(WirelessScanner::channel_to_freq(6), 2437);
        assert_eq!(WirelessScanner::channel_to_freq(11), 2462);
        assert_eq!(WirelessScanner::channel_to_freq(36), 5180);
    }
}
