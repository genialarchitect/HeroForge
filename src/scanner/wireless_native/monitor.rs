//! Monitor mode handling for wireless interfaces
//!
//! Provides functionality to enable/disable monitor mode and manage
//! wireless interface state.

use anyhow::{anyhow, Result};
use std::process::Command;

use super::types::{InterfaceMode, WirelessInterface};

/// Monitor mode manager
pub struct MonitorManager {
    /// Original interface name
    original_interface: String,
    /// Monitor interface name (may differ)
    monitor_interface: Option<String>,
    /// Was monitor mode enabled by us
    enabled_by_us: bool,
}

impl MonitorManager {
    /// Create new monitor manager
    pub fn new(interface: &str) -> Self {
        Self {
            original_interface: interface.to_string(),
            monitor_interface: None,
            enabled_by_us: false,
        }
    }

    /// Enable monitor mode on interface
    pub fn enable(&mut self) -> Result<String> {
        // Check current mode
        let current_mode = get_interface_mode(&self.original_interface)?;

        if current_mode == InterfaceMode::Monitor {
            self.monitor_interface = Some(self.original_interface.clone());
            return Ok(self.original_interface.clone());
        }

        // Try different methods to enable monitor mode

        // Method 1: iw (modern)
        if let Ok(mon_iface) = self.enable_with_iw() {
            self.monitor_interface = Some(mon_iface.clone());
            self.enabled_by_us = true;
            return Ok(mon_iface);
        }

        // Method 2: iwconfig (legacy)
        if let Ok(()) = self.enable_with_iwconfig() {
            self.monitor_interface = Some(self.original_interface.clone());
            self.enabled_by_us = true;
            return Ok(self.original_interface.clone());
        }

        // Method 3: airmon-ng style (create monitor interface)
        if let Ok(mon_iface) = self.create_monitor_interface() {
            self.monitor_interface = Some(mon_iface.clone());
            self.enabled_by_us = true;
            return Ok(mon_iface);
        }

        Err(anyhow!(
            "Failed to enable monitor mode on {}",
            self.original_interface
        ))
    }

    /// Disable monitor mode
    pub fn disable(&mut self) -> Result<()> {
        if !self.enabled_by_us {
            return Ok(());
        }

        if let Some(mon_iface) = &self.monitor_interface {
            if mon_iface != &self.original_interface {
                // Delete monitor interface
                let _ = Command::new("iw")
                    .args(["dev", mon_iface, "del"])
                    .output();
            } else {
                // Restore managed mode
                let _ = Command::new("ip")
                    .args(["link", "set", mon_iface, "down"])
                    .output();

                let _ = Command::new("iw")
                    .args(["dev", mon_iface, "set", "type", "managed"])
                    .output();

                let _ = Command::new("ip")
                    .args(["link", "set", mon_iface, "up"])
                    .output();
            }
        }

        self.monitor_interface = None;
        self.enabled_by_us = false;

        Ok(())
    }

    /// Get monitor interface name
    pub fn get_monitor_interface(&self) -> Option<&str> {
        self.monitor_interface.as_deref()
    }

    /// Enable monitor mode using iw command
    fn enable_with_iw(&self) -> Result<String> {
        // Bring interface down
        Command::new("ip")
            .args(["link", "set", &self.original_interface, "down"])
            .output()
            .map_err(|e| anyhow!("Failed to bring interface down: {}", e))?;

        // Set monitor mode
        let output = Command::new("iw")
            .args(["dev", &self.original_interface, "set", "type", "monitor"])
            .output()
            .map_err(|e| anyhow!("Failed to set monitor mode: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "iw set monitor failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Bring interface up
        Command::new("ip")
            .args(["link", "set", &self.original_interface, "up"])
            .output()
            .map_err(|e| anyhow!("Failed to bring interface up: {}", e))?;

        Ok(self.original_interface.clone())
    }

    /// Enable monitor mode using iwconfig (legacy)
    fn enable_with_iwconfig(&self) -> Result<()> {
        // Bring interface down
        Command::new("ifconfig")
            .args([&self.original_interface, "down"])
            .output()?;

        // Set monitor mode
        let output = Command::new("iwconfig")
            .args([&self.original_interface, "mode", "monitor"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!(
                "iwconfig failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Bring interface up
        Command::new("ifconfig")
            .args([&self.original_interface, "up"])
            .output()?;

        Ok(())
    }

    /// Create a separate monitor interface
    fn create_monitor_interface(&self) -> Result<String> {
        let mon_iface = format!("{}mon", self.original_interface);

        // Add monitor interface
        let output = Command::new("iw")
            .args(["dev", &self.original_interface, "interface", "add", &mon_iface, "type", "monitor"])
            .output()
            .map_err(|e| anyhow!("Failed to create monitor interface: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to create monitor interface: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Bring monitor interface up
        Command::new("ip")
            .args(["link", "set", &mon_iface, "up"])
            .output()?;

        Ok(mon_iface)
    }

    /// Set channel on monitor interface
    pub fn set_channel(&self, channel: u8) -> Result<()> {
        let iface = self.monitor_interface.as_ref()
            .ok_or_else(|| anyhow!("Monitor interface not enabled"))?;

        let output = Command::new("iw")
            .args(["dev", iface, "set", "channel", &channel.to_string()])
            .output()
            .map_err(|e| anyhow!("Failed to set channel: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to set channel {}: {}",
                channel,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }

    /// Set frequency on monitor interface
    pub fn set_frequency(&self, freq_mhz: u32) -> Result<()> {
        let iface = self.monitor_interface.as_ref()
            .ok_or_else(|| anyhow!("Monitor interface not enabled"))?;

        let output = Command::new("iw")
            .args(["dev", iface, "set", "freq", &freq_mhz.to_string()])
            .output()
            .map_err(|e| anyhow!("Failed to set frequency: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "Failed to set frequency {}: {}",
                freq_mhz,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(())
    }
}

impl Drop for MonitorManager {
    fn drop(&mut self) {
        let _ = self.disable();
    }
}

/// Get current interface mode
pub fn get_interface_mode(interface: &str) -> Result<InterfaceMode> {
    // Try iw first
    let output = Command::new("iw")
        .args(["dev", interface, "info"])
        .output();

    if let Ok(output) = output {
        let info = String::from_utf8_lossy(&output.stdout);

        if info.contains("type monitor") {
            return Ok(InterfaceMode::Monitor);
        } else if info.contains("type managed") {
            return Ok(InterfaceMode::Managed);
        } else if info.contains("type AP") || info.contains("type master") {
            return Ok(InterfaceMode::Master);
        } else if info.contains("type IBSS") || info.contains("type ad-hoc") {
            return Ok(InterfaceMode::Adhoc);
        }
    }

    // Fallback to iwconfig
    let output = Command::new("iwconfig")
        .arg(interface)
        .output();

    if let Ok(output) = output {
        let info = String::from_utf8_lossy(&output.stdout);

        if info.contains("Mode:Monitor") {
            return Ok(InterfaceMode::Monitor);
        } else if info.contains("Mode:Managed") {
            return Ok(InterfaceMode::Managed);
        } else if info.contains("Mode:Master") {
            return Ok(InterfaceMode::Master);
        } else if info.contains("Mode:Ad-Hoc") {
            return Ok(InterfaceMode::Adhoc);
        }
    }

    Ok(InterfaceMode::Unknown)
}

/// List all wireless interfaces
pub fn list_wireless_interfaces() -> Result<Vec<WirelessInterface>> {
    let mut interfaces = Vec::new();

    // Use iw to list interfaces
    let output = Command::new("iw")
        .args(["dev"])
        .output()
        .map_err(|e| anyhow!("Failed to list wireless interfaces: {}", e))?;

    let info = String::from_utf8_lossy(&output.stdout);
    let mut current_interface: Option<WirelessInterface> = None;

    for line in info.lines() {
        let line = line.trim();

        if line.starts_with("Interface ") {
            if let Some(iface) = current_interface.take() {
                interfaces.push(iface);
            }

            let name = line.strip_prefix("Interface ").unwrap_or("").to_string();
            current_interface = Some(WirelessInterface {
                name,
                driver: String::new(),
                chipset: None,
                mode: InterfaceMode::Unknown,
                mac_address: String::new(),
                supported_frequencies: Vec::new(),
                monitor_capable: true, // Assume true, will be updated
                injection_capable: false,
            });
        } else if let Some(ref mut iface) = current_interface {
            if line.starts_with("addr ") {
                iface.mac_address = line.strip_prefix("addr ").unwrap_or("").to_string();
            } else if line.starts_with("type ") {
                let mode_str = line.strip_prefix("type ").unwrap_or("");
                iface.mode = match mode_str {
                    "managed" => InterfaceMode::Managed,
                    "monitor" => InterfaceMode::Monitor,
                    "AP" | "master" => InterfaceMode::Master,
                    "IBSS" => InterfaceMode::Adhoc,
                    _ => InterfaceMode::Unknown,
                };
            }
        }
    }

    if let Some(iface) = current_interface {
        interfaces.push(iface);
    }

    // Get driver info for each interface
    for iface in &mut interfaces {
        if let Ok(driver) = get_driver_info(&iface.name) {
            iface.driver = driver.0;
            iface.chipset = driver.1;
        }

        // Check injection capability
        iface.injection_capable = check_injection_capability(&iface.name);
    }

    Ok(interfaces)
}

/// Get driver and chipset info for interface
fn get_driver_info(interface: &str) -> Result<(String, Option<String>)> {
    // Read driver from sysfs
    let driver_path = format!("/sys/class/net/{}/device/driver", interface);

    let driver = if let Ok(link) = std::fs::read_link(&driver_path) {
        link.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        "unknown".to_string()
    };

    // Try to get chipset from lspci/lsusb
    let chipset = None; // Would require parsing lspci/lsusb output

    Ok((driver, chipset))
}

/// Check if interface supports packet injection
fn check_injection_capability(interface: &str) -> bool {
    // Try aireplay-ng injection test (quick test)
    // This is a heuristic - real test would send actual test packets

    let output = Command::new("iw")
        .args(["phy"])
        .output();

    if let Ok(output) = output {
        let info = String::from_utf8_lossy(&output.stdout);

        // Check for interface's phy and see if it supports injection
        // Most modern wireless cards support injection in monitor mode
        // Known good drivers: ath9k, ath9k_htc, rt2800usb, rtl8187, etc.

        let _phy_name = format!("phy#{}", interface);

        // Heuristic: if we can set monitor mode, likely can inject
        return info.contains("monitor");
    }

    false
}

/// Kill interfering processes (NetworkManager, wpa_supplicant, etc.)
pub fn kill_interfering_processes() -> Result<Vec<String>> {
    let mut killed = Vec::new();

    let processes = [
        "NetworkManager",
        "wpa_supplicant",
        "dhclient",
        "dhcpcd",
        "avahi-daemon",
    ];

    for proc in &processes {
        let output = Command::new("pkill")
            .args(["-9", proc])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                killed.push(proc.to_string());
            }
        }
    }

    Ok(killed)
}

/// Restart NetworkManager
pub fn restart_network_manager() -> Result<()> {
    Command::new("systemctl")
        .args(["restart", "NetworkManager"])
        .output()
        .map_err(|e| anyhow!("Failed to restart NetworkManager: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_mode_display() {
        assert_eq!(format!("{}", InterfaceMode::Monitor), "Monitor");
        assert_eq!(format!("{}", InterfaceMode::Managed), "Managed");
    }
}
