//! Native Wireless Security Engine
//!
//! Pure Rust wireless security analysis without Aircrack-ng dependency.
//!
//! # Features
//!
//! - Wireless network scanning and discovery
//! - WPA/WPA2 handshake capture
//! - PMKID extraction for clientless attacks
//! - Rogue access point detection
//! - Security assessment and vulnerability analysis
//! - Native WPA/WPA2 PSK cracking
//!
//! # Requirements
//!
//! - Linux with wireless interface supporting monitor mode
//! - Root or CAP_NET_RAW + CAP_NET_ADMIN capabilities
//!
//! # Example
//!
//! ```rust,ignore
//! use heroforge::scanner::wireless_native::*;
//!
//! // Create scanner
//! let config = WirelessScanConfig::default();
//! let mut scanner = WirelessScanner::new(config);
//!
//! // Start scanning
//! scanner.start()?;
//!
//! // ... wait for results ...
//!
//! // Stop and get results
//! let results = scanner.stop()?;
//!
//! // Assess security
//! for ap in &results.access_points {
//!     let assessment = assess_security(ap);
//!     println!("AP {} rating: {}/100", ap.ssid.as_deref().unwrap_or("hidden"), assessment.security_rating);
//! }
//!
//! // Crack captured handshakes
//! let cracker = WpaCracker::new(WpaCrackerConfig::default());
//! for handshake in &results.handshakes {
//!     if handshake.is_crackable() {
//!         let result = cracker.crack_handshake(handshake, &wordlist)?;
//!         if result.success {
//!             println!("Cracked: {}", result.password.unwrap());
//!         }
//!     }
//! }
//! ```

pub mod types;
pub mod monitor;
pub mod scanner;
pub mod handshake;
pub mod analysis;
pub mod cracking;

pub use types::*;
pub use monitor::list_wireless_interfaces;
pub use scanner::WirelessScanner;
pub use handshake::PmkidExtractor;
pub use analysis::{
    generate_security_report, WirelessSecurityReport,
    RogueApDetector,
};
pub use cracking::{
    WpaCracker, WpaCrackerConfig, WpaCrackResult,
};

use anyhow::Result;

/// Native wireless security scanner
///
/// Provides comprehensive wireless security assessment without external tools.
pub struct NativeWirelessScanner {
    /// Scanner instance
    scanner: Option<WirelessScanner>,
    /// Rogue AP detector
    rogue_detector: RogueApDetector,
    /// PMKID extractor
    pmkid_extractor: PmkidExtractor,
    /// Cracker
    cracker: WpaCracker,
}

impl NativeWirelessScanner {
    /// Create new native wireless scanner
    pub fn new() -> Self {
        Self {
            scanner: None,
            rogue_detector: RogueApDetector::new(),
            pmkid_extractor: PmkidExtractor::new(),
            cracker: WpaCracker::new(WpaCrackerConfig::default()),
        }
    }

    /// Initialize with interface
    pub fn init(&mut self, config: WirelessScanConfig) -> Result<()> {
        self.scanner = Some(WirelessScanner::new(config));
        Ok(())
    }

    /// Start scanning
    pub fn start_scan(&mut self) -> Result<()> {
        if let Some(ref mut scanner) = self.scanner {
            scanner.start()?;
        }
        Ok(())
    }

    /// Stop scanning and get results
    pub fn stop_scan(&mut self) -> Result<WirelessScanResult> {
        if let Some(ref mut scanner) = self.scanner {
            scanner.stop()
        } else {
            Ok(WirelessScanResult::default())
        }
    }

    /// Get current scan results (live)
    pub fn get_current_results(&self) -> Option<WirelessScanResult> {
        self.scanner.as_ref().map(|s| s.get_current_results())
    }

    /// Load baseline for rogue AP detection
    pub fn load_baseline(&mut self, aps: &[AccessPoint]) {
        self.rogue_detector.load_baseline(aps);
    }

    /// Detect rogue APs
    pub fn detect_rogue_aps(&mut self, aps: &[AccessPoint]) -> Vec<RogueApDetection> {
        self.rogue_detector.analyze(aps)
    }

    /// Assess security of all APs
    pub fn assess_all_security(&self, aps: &[AccessPoint]) -> WirelessSecurityReport {
        generate_security_report(aps)
    }

    /// Crack handshake
    pub fn crack_handshake(&self, handshake: &CapturedHandshake,
                           wordlist: &[String]) -> Result<WpaCrackResult> {
        self.cracker.crack_handshake(handshake, wordlist)
    }

    /// Crack PMKID
    pub fn crack_pmkid(&self, pmkid: &PmkidData,
                       wordlist: &[String]) -> Result<WpaCrackResult> {
        self.cracker.crack_pmkid(pmkid, wordlist)
    }
}

impl Default for NativeWirelessScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if wireless capabilities are available
pub fn check_wireless_capabilities() -> WirelessCapabilities {
    let interfaces = list_wireless_interfaces().unwrap_or_default();

    let has_wireless = !interfaces.is_empty();
    let has_monitor = interfaces.iter().any(|i| i.monitor_capable);
    let has_injection = interfaces.iter().any(|i| i.injection_capable);

    // Check for root/capabilities
    let has_root = unsafe { libc::geteuid() == 0 };

    // Check for CAP_NET_RAW (simplified - assumes root has it)
    let has_net_raw = has_root;

    WirelessCapabilities {
        has_wireless,
        has_monitor,
        has_injection,
        has_root,
        has_net_raw,
        interfaces,
    }
}

/// Wireless capabilities check result
#[derive(Debug, Clone)]
pub struct WirelessCapabilities {
    /// Has wireless interface
    pub has_wireless: bool,
    /// Has monitor mode capable interface
    pub has_monitor: bool,
    /// Has injection capable interface
    pub has_injection: bool,
    /// Running as root
    pub has_root: bool,
    /// Has CAP_NET_RAW capability
    pub has_net_raw: bool,
    /// Available interfaces
    pub interfaces: Vec<WirelessInterface>,
}

impl WirelessCapabilities {
    /// Check if scanning is possible
    pub fn can_scan(&self) -> bool {
        self.has_wireless && self.has_monitor && (self.has_root || self.has_net_raw)
    }

    /// Check if attacks are possible
    pub fn can_attack(&self) -> bool {
        self.can_scan() && self.has_injection
    }

    /// Get first suitable interface
    pub fn get_suitable_interface(&self) -> Option<&WirelessInterface> {
        self.interfaces.iter()
            .find(|i| i.monitor_capable)
    }

    /// Format capabilities as string
    pub fn format(&self) -> String {
        let mut lines = Vec::new();

        lines.push(format!("Wireless interfaces: {}", if self.has_wireless { "Yes" } else { "No" }));
        lines.push(format!("Monitor mode: {}", if self.has_monitor { "Yes" } else { "No" }));
        lines.push(format!("Packet injection: {}", if self.has_injection { "Yes" } else { "No" }));
        lines.push(format!("Root privileges: {}", if self.has_root { "Yes" } else { "No" }));
        lines.push(format!("CAP_NET_RAW: {}", if self.has_net_raw { "Yes" } else { "No" }));

        if !self.interfaces.is_empty() {
            lines.push("\nInterfaces:".to_string());
            for iface in &self.interfaces {
                lines.push(format!(
                    "  {} ({}) - {} {}{}",
                    iface.name,
                    iface.driver,
                    iface.mode,
                    if iface.monitor_capable { "[Monitor]" } else { "" },
                    if iface.injection_capable { "[Inject]" } else { "" }
                ));
            }
        }

        lines.join("\n")
    }
}

/// Quick scan for nearby networks
pub fn quick_scan(interface: &str, duration_secs: u32) -> Result<Vec<AccessPoint>> {
    let config = WirelessScanConfig {
        interface: interface.to_string(),
        channels: vec![1, 6, 11, 36, 40, 44, 48], // Common channels
        hop_interval_ms: 200,
        duration_secs,
        capture_handshakes: false,
        capture_pmkid: false,
        active_probe: false,
        discover_hidden: false,
        bssid_filter: None,
        ssid_filter: None,
    };

    let mut scanner = WirelessScanner::new(config);
    scanner.start()?;

    std::thread::sleep(std::time::Duration::from_secs(duration_secs as u64));

    let results = scanner.stop()?;
    Ok(results.access_points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_format() {
        let caps = WirelessCapabilities {
            has_wireless: true,
            has_monitor: true,
            has_injection: false,
            has_root: false,
            has_net_raw: true,
            interfaces: Vec::new(),
        };

        let formatted = caps.format();
        assert!(formatted.contains("Wireless interfaces: Yes"));
        assert!(formatted.contains("Monitor mode: Yes"));
    }
}
