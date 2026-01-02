//! Rogue access point detection
//!
//! Detect evil twin attacks, unauthorized APs, and karma attacks.

use chrono::Utc;
use std::collections::HashMap;

use crate::scanner::wireless_native::types::*;

/// Rogue AP detector
pub struct RogueApDetector {
    /// Known legitimate access points (BSSID -> AP info)
    authorized_aps: HashMap<String, AuthorizedApInfo>,
    /// Known SSIDs (SSID -> expected BSSID)
    known_ssids: HashMap<String, Vec<String>>,
    /// Detection history
    detections: Vec<RogueApDetection>,
}

/// Authorized AP information
#[derive(Debug, Clone)]
pub struct AuthorizedApInfo {
    /// BSSID
    pub bssid: String,
    /// Expected SSID
    pub ssid: String,
    /// Expected channel
    pub channel: Option<u8>,
    /// Expected security type
    pub security: Option<SecurityType>,
    /// Manufacturer
    pub manufacturer: Option<String>,
}

impl RogueApDetector {
    /// Create new rogue AP detector
    pub fn new() -> Self {
        Self {
            authorized_aps: HashMap::new(),
            known_ssids: HashMap::new(),
            detections: Vec::new(),
        }
    }

    /// Add an authorized AP
    pub fn add_authorized_ap(&mut self, info: AuthorizedApInfo) {
        let ssid = info.ssid.clone();
        let bssid = info.bssid.clone();

        self.authorized_aps.insert(bssid.clone(), info);

        self.known_ssids
            .entry(ssid)
            .or_insert_with(Vec::new)
            .push(bssid);
    }

    /// Load authorized APs from existing scan
    pub fn load_baseline(&mut self, aps: &[AccessPoint]) {
        for ap in aps {
            if let Some(ssid) = &ap.ssid {
                self.add_authorized_ap(AuthorizedApInfo {
                    bssid: ap.bssid.clone(),
                    ssid: ssid.clone(),
                    channel: Some(ap.channel),
                    security: Some(ap.security),
                    manufacturer: ap.manufacturer.clone(),
                });
            }
        }
    }

    /// Analyze APs for rogue access points
    pub fn analyze(&mut self, aps: &[AccessPoint]) -> Vec<RogueApDetection> {
        let mut detections = Vec::new();

        for ap in aps {
            // Check for various rogue AP indicators
            if let Some(detection) = self.check_ssid_duplicate(ap) {
                detections.push(detection);
            }

            if let Some(detection) = self.check_evil_twin(ap) {
                detections.push(detection);
            }

            if let Some(detection) = self.check_unauthorized(ap) {
                detections.push(detection);
            }

            if let Some(detection) = self.check_mac_spoofing(ap) {
                detections.push(detection);
            }
        }

        // Check for karma attack (responds to many probe requests)
        if let Some(detection) = self.check_karma_attack(aps) {
            detections.push(detection);
        }

        self.detections.extend(detections.clone());

        detections
    }

    /// Check for SSID duplicate (same SSID, different BSSID)
    fn check_ssid_duplicate(&self, ap: &AccessPoint) -> Option<RogueApDetection> {
        let ssid = ap.ssid.as_ref()?;

        if let Some(known_bssids) = self.known_ssids.get(ssid) {
            // If this BSSID is not in the known list for this SSID
            if !known_bssids.contains(&ap.bssid) && !known_bssids.is_empty() {
                // Find the legitimate AP for comparison
                let legitimate_bssid = known_bssids.first()?;
                let legitimate_ap = self.authorized_aps.get(legitimate_bssid)?;

                return Some(RogueApDetection {
                    rogue_ap: ap.clone(),
                    legitimate_ap: Some(AccessPoint {
                        bssid: legitimate_ap.bssid.clone(),
                        ssid: Some(legitimate_ap.ssid.clone()),
                        hidden: false,
                        channel: legitimate_ap.channel.unwrap_or(0),
                        frequency: 0,
                        signal_dbm: 0,
                        signal_quality: 0,
                        security: legitimate_ap.security.unwrap_or(SecurityType::Unknown),
                        ciphers: Vec::new(),
                        auth_methods: Vec::new(),
                        wpa_versions: Vec::new(),
                        wps_enabled: false,
                        wps_locked: false,
                        manufacturer: legitimate_ap.manufacturer.clone(),
                        clients: Vec::new(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        beacon_count: 0,
                        data_count: 0,
                    }),
                    detection_type: RogueApType::SsidDuplicate,
                    confidence: 70,
                    reason: format!(
                        "SSID '{}' found with unknown BSSID {} (expected: {})",
                        ssid, ap.bssid, legitimate_bssid
                    ),
                    detected_at: Utc::now(),
                });
            }
        }

        None
    }

    /// Check for evil twin (same SSID + security, different BSSID)
    fn check_evil_twin(&self, ap: &AccessPoint) -> Option<RogueApDetection> {
        let ssid = ap.ssid.as_ref()?;

        if let Some(known_bssids) = self.known_ssids.get(ssid) {
            if !known_bssids.contains(&ap.bssid) && !known_bssids.is_empty() {
                let legitimate_bssid = known_bssids.first()?;
                let legitimate_info = self.authorized_aps.get(legitimate_bssid)?;

                // Check if security matches (evil twin mimics security settings)
                let security_matches = legitimate_info.security
                    .map(|s| s == ap.security)
                    .unwrap_or(false);

                if security_matches {
                    return Some(RogueApDetection {
                        rogue_ap: ap.clone(),
                        legitimate_ap: None,
                        detection_type: RogueApType::EvilTwin,
                        confidence: 85,
                        reason: format!(
                            "Evil twin detected: SSID '{}' with matching security at BSSID {}",
                            ssid, ap.bssid
                        ),
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        None
    }

    /// Check for unauthorized AP (unknown BSSID)
    fn check_unauthorized(&self, ap: &AccessPoint) -> Option<RogueApDetection> {
        // If we have a baseline and this AP is not in it
        if !self.authorized_aps.is_empty() && !self.authorized_aps.contains_key(&ap.bssid) {
            return Some(RogueApDetection {
                rogue_ap: ap.clone(),
                legitimate_ap: None,
                detection_type: RogueApType::UnauthorizedAp,
                confidence: 50,
                reason: format!(
                    "Unauthorized AP detected: BSSID {} SSID '{}'",
                    ap.bssid, ap.ssid.as_deref().unwrap_or("(hidden)")
                ),
                detected_at: Utc::now(),
            });
        }

        None
    }

    /// Check for MAC spoofing (BSSID matches but characteristics differ)
    fn check_mac_spoofing(&self, ap: &AccessPoint) -> Option<RogueApDetection> {
        if let Some(known_ap) = self.authorized_aps.get(&ap.bssid) {
            let mut anomalies = Vec::new();

            // Check if channel changed significantly
            if let Some(known_channel) = known_ap.channel {
                if ap.channel != known_channel {
                    anomalies.push(format!(
                        "channel changed from {} to {}",
                        known_channel, ap.channel
                    ));
                }
            }

            // Check if security changed
            if let Some(known_security) = known_ap.security {
                if ap.security != known_security {
                    anomalies.push(format!(
                        "security changed from {} to {}",
                        known_security, ap.security
                    ));
                }
            }

            // Check if SSID changed for same BSSID
            if let Some(ref ssid) = ap.ssid {
                if *ssid != known_ap.ssid {
                    anomalies.push(format!(
                        "SSID changed from '{}' to '{}'",
                        known_ap.ssid, ssid
                    ));
                }
            }

            if !anomalies.is_empty() {
                return Some(RogueApDetection {
                    rogue_ap: ap.clone(),
                    legitimate_ap: None,
                    detection_type: RogueApType::MacSpoofing,
                    confidence: 75,
                    reason: format!(
                        "Possible MAC spoofing detected for {}: {}",
                        ap.bssid, anomalies.join(", ")
                    ),
                    detected_at: Utc::now(),
                });
            }
        }

        None
    }

    /// Check for karma attack (AP responding to many probe requests)
    fn check_karma_attack(&self, aps: &[AccessPoint]) -> Option<RogueApDetection> {
        // A karma attack AP typically advertises many different SSIDs
        // Group APs by BSSID and check for multiple SSIDs

        let mut bssid_ssids: HashMap<&str, Vec<&str>> = HashMap::new();

        for ap in aps {
            if let Some(ref ssid) = ap.ssid {
                bssid_ssids
                    .entry(&ap.bssid)
                    .or_insert_with(Vec::new)
                    .push(ssid);
            }
        }

        for (bssid, ssids) in bssid_ssids {
            // If same BSSID is advertising 3+ different SSIDs, likely karma attack
            if ssids.len() >= 3 {
                // Get one of the APs for this BSSID
                let rogue_ap = aps.iter()
                    .find(|ap| ap.bssid == bssid)
                    .cloned()?;

                return Some(RogueApDetection {
                    rogue_ap,
                    legitimate_ap: None,
                    detection_type: RogueApType::KarmaAttack,
                    confidence: 90,
                    reason: format!(
                        "Karma attack suspected: BSSID {} advertising {} SSIDs: {:?}",
                        bssid, ssids.len(), ssids
                    ),
                    detected_at: Utc::now(),
                });
            }
        }

        None
    }

    /// Get all detections
    pub fn get_detections(&self) -> &[RogueApDetection] {
        &self.detections
    }

    /// Clear detection history
    pub fn clear_detections(&mut self) {
        self.detections.clear();
    }
}

impl Default for RogueApDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect APs with unusually strong signals (might be local rogue)
pub fn detect_signal_anomalies(aps: &[AccessPoint]) -> Vec<&AccessPoint> {
    // APs with very strong signals (-30 dBm or better) in unusual locations
    // might indicate a close-proximity rogue AP
    aps.iter()
        .filter(|ap| ap.signal_dbm >= -30)
        .collect()
}

/// Check for APs on non-standard channels
pub fn detect_unusual_channels(aps: &[AccessPoint]) -> Vec<&AccessPoint> {
    // Standard 2.4 GHz channels are 1, 6, 11 (non-overlapping)
    // APs on other channels might be trying to avoid detection
    let standard_channels = [1, 6, 11];

    aps.iter()
        .filter(|ap| ap.channel <= 14 && !standard_channels.contains(&ap.channel))
        .collect()
}

/// Analyze probe requests for suspicious patterns
pub fn analyze_client_probes(clients: &[WirelessClient]) -> Vec<SuspiciousProbePattern> {
    let mut patterns = Vec::new();

    for client in clients {
        // Client probing for many networks might be compromised device
        if client.probes.len() > 20 {
            patterns.push(SuspiciousProbePattern {
                client_mac: client.mac_address.clone(),
                pattern_type: ProbePatternType::ExcessiveProbing,
                description: format!(
                    "Client probing for {} networks - possible reconnaissance",
                    client.probes.len()
                ),
            });
        }

        // Check for common attack tool SSIDs in probes
        let attack_ssids = ["Free WiFi", "Free Wifi", "TEST", "test", "hacker",
                          "pwned", "EvilTwin", "OpenWiFi", "Open Wifi"];

        for ssid in &client.probes {
            if attack_ssids.iter().any(|a| ssid.contains(a)) {
                patterns.push(SuspiciousProbePattern {
                    client_mac: client.mac_address.clone(),
                    pattern_type: ProbePatternType::SuspiciousSsid,
                    description: format!(
                        "Client probing for suspicious SSID: '{}'",
                        ssid
                    ),
                });
            }
        }
    }

    patterns
}

/// Suspicious probe pattern
#[derive(Debug, Clone)]
pub struct SuspiciousProbePattern {
    pub client_mac: String,
    pub pattern_type: ProbePatternType,
    pub description: String,
}

/// Types of suspicious probe patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePatternType {
    /// Too many probe requests
    ExcessiveProbing,
    /// Probing for known attack SSIDs
    SuspiciousSsid,
    /// Probing for enterprise networks from unexpected location
    EnterpriseProbe,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ap(bssid: &str, ssid: &str, security: SecurityType) -> AccessPoint {
        AccessPoint {
            bssid: bssid.to_string(),
            ssid: Some(ssid.to_string()),
            hidden: false,
            channel: 6,
            frequency: 2437,
            signal_dbm: -50,
            signal_quality: 80,
            security,
            ciphers: vec![CipherSuite::Ccmp],
            auth_methods: vec![AuthMethod::Psk],
            wpa_versions: vec![WpaVersion::Wpa2],
            wps_enabled: false,
            wps_locked: false,
            manufacturer: None,
            clients: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            beacon_count: 100,
            data_count: 50,
        }
    }

    #[test]
    fn test_ssid_duplicate_detection() {
        let mut detector = RogueApDetector::new();

        // Add authorized AP
        detector.add_authorized_ap(AuthorizedApInfo {
            bssid: "00:11:22:33:44:55".to_string(),
            ssid: "CorpNetwork".to_string(),
            channel: Some(6),
            security: Some(SecurityType::WPA2),
            manufacturer: None,
        });

        // Test with rogue AP using same SSID
        let rogue = create_test_ap("AA:BB:CC:DD:EE:FF", "CorpNetwork", SecurityType::WPA2);

        let detections = detector.analyze(&[rogue]);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| matches!(d.detection_type, RogueApType::SsidDuplicate | RogueApType::EvilTwin)));
    }

    #[test]
    fn test_karma_detection() {
        let mut detector = RogueApDetector::new();

        // Create multiple APs with same BSSID but different SSIDs
        let karma_aps = vec![
            create_test_ap("AA:BB:CC:DD:EE:FF", "Network1", SecurityType::Open),
            create_test_ap("AA:BB:CC:DD:EE:FF", "Network2", SecurityType::Open),
            create_test_ap("AA:BB:CC:DD:EE:FF", "Network3", SecurityType::Open),
            create_test_ap("AA:BB:CC:DD:EE:FF", "Network4", SecurityType::Open),
        ];

        let detections = detector.analyze(&karma_aps);

        assert!(detections.iter().any(|d| d.detection_type == RogueApType::KarmaAttack));
    }
}
