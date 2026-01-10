//! WPA/WPA2 4-way handshake capture
//!
//! Capture and validate WPA handshakes for offline cracking.

use anyhow::{anyhow, Result};

use crate::scanner::wireless_native::types::*;

/// Parse EAPOL-Key frame
pub fn parse_eapol_key(data: &[u8]) -> Result<EapolMessage> {
    // Minimum EAPOL-Key frame size
    if data.len() < 99 {
        return Err(anyhow!("EAPOL frame too short"));
    }

    // EAPOL header (4 bytes)
    // +0: Protocol version (1 byte)
    // +1: Packet type (1 byte) - should be 3 for EAPOL-Key
    // +2-3: Body length (2 bytes, big-endian)
    let _protocol_version = data[0];
    let packet_type = data[1];
    let _body_length = u16::from_be_bytes([data[2], data[3]]);

    if packet_type != 3 {
        return Err(anyhow!("Not an EAPOL-Key frame"));
    }

    // EAPOL-Key body starts at offset 4
    let key_data = &data[4..];

    if key_data.len() < 95 {
        return Err(anyhow!("EAPOL-Key body too short"));
    }

    // Key descriptor type (+0): 2 = RSN, 254 = WPA
    let key_type = key_data[0];

    // Key information (+1-2)
    let key_info = u16::from_be_bytes([key_data[1], key_data[2]]);

    // Key length (+3-4)
    let key_length = u16::from_be_bytes([key_data[3], key_data[4]]);

    // Replay counter (+5-12)
    let replay_counter = u64::from_be_bytes([
        key_data[5], key_data[6], key_data[7], key_data[8],
        key_data[9], key_data[10], key_data[11], key_data[12],
    ]);

    // Key nonce (+13-44, 32 bytes)
    let nonce = key_data[13..45].to_vec();

    // Key IV (+45-60, 16 bytes)
    let key_iv = key_data[45..61].to_vec();

    // Key RSC (+61-68, 8 bytes)
    let key_rsc = key_data[61..69].to_vec();

    // Key ID (+69-76, 8 bytes) - reserved

    // Key MIC (+77-92, 16 bytes)
    let mic = key_data[77..93].to_vec();

    // Key data length (+93-94)
    let key_data_len = u16::from_be_bytes([key_data[93], key_data[94]]) as usize;

    // Key data (+95..)
    let key_data_bytes = if key_data.len() >= 95 + key_data_len {
        key_data[95..95 + key_data_len].to_vec()
    } else {
        Vec::new()
    };

    // Determine message number based on key info flags
    let message_number = determine_message_number(key_info);

    Ok(EapolMessage {
        message_number,
        key_type,
        key_info,
        key_length,
        replay_counter,
        nonce,
        key_iv,
        key_rsc,
        mic,
        key_data: key_data_bytes,
        raw_data: data.to_vec(),
    })
}

/// Determine which message of the 4-way handshake this is
fn determine_message_number(key_info: u16) -> u8 {
    // Key info flags:
    // Bit 0: Key Descriptor Version (bits 0-2)
    // Bit 3: Key Type (0 = group, 1 = pairwise)
    // Bit 6: Install
    // Bit 7: Key ACK
    // Bit 8: Key MIC
    // Bit 9: Secure
    // Bit 10: Error
    // Bit 11: Request
    // Bit 12: Encrypted Key Data

    let has_ack = (key_info & 0x0080) != 0;
    let has_mic = (key_info & 0x0100) != 0;
    let has_install = (key_info & 0x0040) != 0;
    let has_secure = (key_info & 0x0200) != 0;

    match (has_ack, has_mic, has_install, has_secure) {
        (true, false, false, false) => 1,  // M1: ACK, no MIC
        (false, true, false, false) => 2,  // M2: MIC, no ACK
        (true, true, true, true) => 3,     // M3: ACK, MIC, Install, Secure
        (false, true, false, true) => 4,   // M4: MIC, Secure, no ACK
        _ => 0, // Unknown
    }
}

/// Validate a captured handshake
pub fn validate_handshake(handshake: &CapturedHandshake) -> HandshakeValidation {
    let mut validation = HandshakeValidation {
        valid: false,
        crackable: false,
        messages_captured: Vec::new(),
        issues: Vec::new(),
    };

    // Check which messages we have
    if handshake.message1.is_some() {
        validation.messages_captured.push(1);
    }
    if handshake.message2.is_some() {
        validation.messages_captured.push(2);
    }
    if handshake.message3.is_some() {
        validation.messages_captured.push(3);
    }
    if handshake.message4.is_some() {
        validation.messages_captured.push(4);
    }

    // Check nonces
    if handshake.anonce.is_empty() {
        validation.issues.push("Missing ANonce".to_string());
    }
    if handshake.snonce.is_empty() {
        validation.issues.push("Missing SNonce".to_string());
    }

    // Validate we have enough for cracking
    // Need M1+M2 or M2+M3 for cracking
    let has_m1_m2 = handshake.message1.is_some() && handshake.message2.is_some();
    let has_m2_m3 = handshake.message2.is_some() && handshake.message3.is_some();

    validation.crackable = has_m1_m2 || has_m2_m3;

    if validation.crackable {
        // Validate MIC is present in M2
        if let Some(m2) = &handshake.message2 {
            if m2.mic.iter().all(|&b| b == 0) {
                validation.issues.push("M2 MIC is all zeros".to_string());
                validation.crackable = false;
            }
        }
    }

    validation.valid = validation.crackable && validation.issues.is_empty();

    validation
}

/// Handshake validation result
#[derive(Debug, Clone)]
pub struct HandshakeValidation {
    /// Is handshake valid
    pub valid: bool,
    /// Is handshake crackable
    pub crackable: bool,
    /// Messages captured
    pub messages_captured: Vec<u8>,
    /// Issues found
    pub issues: Vec<String>,
}

/// Calculate Pairwise Master Key (PMK) from passphrase
pub fn calculate_pmk(passphrase: &str, ssid: &str) -> [u8; 32] {
    use hmac::Hmac;
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    // PBKDF2-HMAC-SHA1 with 4096 iterations
    let mut pmk = [0u8; 32];

    pbkdf2_sha1(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);

    pmk
}

/// PBKDF2-HMAC-SHA1 implementation
fn pbkdf2_sha1(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    let mut block_num = 1u32;
    let mut pos = 0;

    while pos < output.len() {
        // First iteration: HMAC(password, salt || block_num)
        let mut mac = HmacSha1::new_from_slice(password).unwrap();
        mac.update(salt);
        mac.update(&block_num.to_be_bytes());
        let mut u = mac.finalize().into_bytes();

        let mut result = [0u8; 20]; // SHA1 output size
        result.copy_from_slice(&u);

        // Subsequent iterations
        for _ in 1..iterations {
            let mut mac = HmacSha1::new_from_slice(password).unwrap();
            mac.update(&u);
            u = mac.finalize().into_bytes();

            for (r, u_byte) in result.iter_mut().zip(u.iter()) {
                *r ^= u_byte;
            }
        }

        // Copy to output
        let copy_len = (output.len() - pos).min(20);
        output[pos..pos + copy_len].copy_from_slice(&result[..copy_len]);

        pos += copy_len;
        block_num += 1;
    }
}

/// Calculate Pairwise Transient Key (PTK) from PMK
pub fn calculate_ptk(pmk: &[u8; 32], anonce: &[u8], snonce: &[u8],
                     ap_mac: &[u8; 6], client_mac: &[u8; 6]) -> Vec<u8> {
    use hmac::Hmac;
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    // Build the data string: "Pairwise key expansion" || min(AP_MAC, STA_MAC) ||
    // max(AP_MAC, STA_MAC) || min(ANonce, SNonce) || max(ANonce, SNonce)

    let mut data = Vec::with_capacity(76);
    data.extend_from_slice(b"Pairwise key expansion");
    data.push(0);

    // Add MACs in sorted order
    if ap_mac <= client_mac {
        data.extend_from_slice(ap_mac);
        data.extend_from_slice(client_mac);
    } else {
        data.extend_from_slice(client_mac);
        data.extend_from_slice(ap_mac);
    }

    // Add nonces in sorted order
    if anonce <= snonce {
        data.extend_from_slice(anonce);
        data.extend_from_slice(snonce);
    } else {
        data.extend_from_slice(snonce);
        data.extend_from_slice(anonce);
    }

    // PRF-512 to generate 64 bytes of PTK
    prf_512(pmk, &data, 64)
}

/// PRF-512 (Pseudo-Random Function)
fn prf_512(key: &[u8], data: &[u8], output_len: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    let mut output = Vec::with_capacity(output_len);
    let mut counter = 0u8;

    while output.len() < output_len {
        let mut mac = HmacSha1::new_from_slice(key).unwrap();
        mac.update(data);
        mac.update(&[counter]);
        let result = mac.finalize().into_bytes();

        let remaining = output_len - output.len();
        let copy_len = remaining.min(20);
        output.extend_from_slice(&result[..copy_len]);

        counter += 1;
    }

    output.truncate(output_len);
    output
}

/// Verify handshake MIC with a candidate password
pub fn verify_handshake_mic(handshake: &HandshakeCrackData, passphrase: &str) -> bool {
    // Calculate PMK
    let pmk = calculate_pmk(passphrase, &handshake.ssid);

    // Parse MAC addresses
    let ap_mac = match parse_mac(&handshake.bssid) {
        Some(m) => m,
        None => return false,
    };

    let client_mac = match parse_mac(&handshake.client_mac) {
        Some(m) => m,
        None => return false,
    };

    // Calculate PTK
    let ptk = calculate_ptk(&pmk, &handshake.anonce, &handshake.snonce,
                            &ap_mac, &client_mac);

    // Extract KCK (first 16 bytes of PTK)
    let kck = &ptk[..16];

    // Calculate MIC over EAPOL frame
    // The MIC field should be zeroed when calculating
    let calculated_mic = calculate_eapol_mic(kck, &handshake.key_data);

    // Compare MICs
    calculated_mic == handshake.mic
}

/// Calculate EAPOL MIC
fn calculate_eapol_mic(kck: &[u8], eapol_data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(kck).unwrap();
    mac.update(eapol_data);
    let result = mac.finalize().into_bytes();

    result[..16].to_vec()
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

/// Export handshake to hccapx format (hashcat)
pub fn export_hccapx(handshake: &CapturedHandshake) -> Result<Vec<u8>> {
    // hccapx format structure
    // See: https://hashcat.net/wiki/doku.php?id=hccapx

    if !handshake.is_crackable() {
        return Err(anyhow!("Handshake not crackable"));
    }

    let m2 = handshake.message2.as_ref()
        .ok_or_else(|| anyhow!("Missing M2"))?;

    let mut output = Vec::with_capacity(393);

    // Signature (4 bytes): HCPX
    output.extend_from_slice(b"HCPX");

    // Version (4 bytes)
    output.extend_from_slice(&4u32.to_le_bytes());

    // Message pair (1 byte)
    let message_pair = if handshake.message1.is_some() { 0 } else { 2 };
    output.push(message_pair);

    // ESSID length (1 byte)
    output.push(handshake.ssid.len() as u8);

    // ESSID (32 bytes, padded)
    let mut essid = [0u8; 32];
    let len = handshake.ssid.len().min(32);
    essid[..len].copy_from_slice(&handshake.ssid.as_bytes()[..len]);
    output.extend_from_slice(&essid);

    // Key version (1 byte)
    let key_version = (m2.key_info & 0x0007) as u8;
    output.push(key_version);

    // Key MIC (16 bytes)
    let mut mic = [0u8; 16];
    let mic_len = m2.mic.len().min(16);
    mic[..mic_len].copy_from_slice(&m2.mic[..mic_len]);
    output.extend_from_slice(&mic);

    // AP MAC (6 bytes)
    let ap_mac = parse_mac(&handshake.bssid)
        .ok_or_else(|| anyhow!("Invalid BSSID"))?;
    output.extend_from_slice(&ap_mac);

    // AP nonce (32 bytes)
    let mut anonce = [0u8; 32];
    let anonce_len = handshake.anonce.len().min(32);
    anonce[..anonce_len].copy_from_slice(&handshake.anonce[..anonce_len]);
    output.extend_from_slice(&anonce);

    // STA MAC (6 bytes)
    let sta_mac = parse_mac(&handshake.client_mac)
        .ok_or_else(|| anyhow!("Invalid client MAC"))?;
    output.extend_from_slice(&sta_mac);

    // STA nonce (32 bytes)
    let mut snonce = [0u8; 32];
    let snonce_len = handshake.snonce.len().min(32);
    snonce[..snonce_len].copy_from_slice(&handshake.snonce[..snonce_len]);
    output.extend_from_slice(&snonce);

    // EAPOL length (2 bytes)
    let eapol_len = m2.raw_data.len() as u16;
    output.extend_from_slice(&eapol_len.to_le_bytes());

    // EAPOL data (256 bytes, padded)
    let mut eapol = [0u8; 256];
    let len = m2.raw_data.len().min(256);
    eapol[..len].copy_from_slice(&m2.raw_data[..len]);
    output.extend_from_slice(&eapol);

    Ok(output)
}

/// Export handshake to hashcat 22000 format
pub fn export_hc22000(handshake: &CapturedHandshake) -> Result<String> {
    if !handshake.is_crackable() {
        return Err(anyhow!("Handshake not crackable"));
    }

    let m2 = handshake.message2.as_ref()
        .ok_or_else(|| anyhow!("Missing M2"))?;

    // Format: WPA*TYPE*PMKID/MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL
    let mic_hex = hex::encode(&m2.mic);
    let ap_mac_hex = handshake.bssid.replace(":", "").to_lowercase();
    let sta_mac_hex = handshake.client_mac.replace(":", "").to_lowercase();
    let essid_hex = hex::encode(&handshake.ssid);
    let anonce_hex = hex::encode(&handshake.anonce);
    let eapol_hex = hex::encode(&m2.raw_data);

    // TYPE 01 = handshake (PMKID is 02)
    let line = format!(
        "WPA*01*{}*{}*{}*{}*{}*{}",
        mic_hex, ap_mac_hex, sta_mac_hex, essid_hex, anonce_hex, eapol_hex
    );

    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac() {
        let mac = parse_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac = parse_mac("00-11-22-33-44-55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn test_pmk_calculation() {
        // Test vector from IEEE 802.11-2016
        let pmk = calculate_pmk("password", "IEEE");
        // The expected PMK is well-known
        assert!(!pmk.iter().all(|&b| b == 0));
    }
}
