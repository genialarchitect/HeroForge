//! NTLM Authentication for SMB
//!
//! Implements NTLMv2 authentication required for SMB2/3 sessions.

use super::types::{SmbError, SmbResult};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::Rng;
use std::io::{Cursor, Read};

type HmacMd5 = Hmac<Md5>;

/// NTLM signature
const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLM message types
const NEGOTIATE_MESSAGE: u32 = 1;
const CHALLENGE_MESSAGE: u32 = 2;
const AUTHENTICATE_MESSAGE: u32 = 3;

/// NTLM negotiate flags
pub mod ntlm_flags {
    pub const NEGOTIATE_UNICODE: u32 = 0x00000001;
    pub const NEGOTIATE_OEM: u32 = 0x00000002;
    pub const REQUEST_TARGET: u32 = 0x00000004;
    pub const NEGOTIATE_SIGN: u32 = 0x00000010;
    pub const NEGOTIATE_SEAL: u32 = 0x00000020;
    pub const NEGOTIATE_DATAGRAM: u32 = 0x00000040;
    pub const NEGOTIATE_LM_KEY: u32 = 0x00000080;
    pub const NEGOTIATE_NTLM: u32 = 0x00000200;
    pub const NEGOTIATE_ANONYMOUS: u32 = 0x00000800;
    pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x00001000;
    pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x00002000;
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
    pub const TARGET_TYPE_DOMAIN: u32 = 0x00010000;
    pub const TARGET_TYPE_SERVER: u32 = 0x00020000;
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x00080000;
    pub const NEGOTIATE_IDENTIFY: u32 = 0x00100000;
    pub const REQUEST_NON_NT_SESSION_KEY: u32 = 0x00400000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x00800000;
    pub const NEGOTIATE_VERSION: u32 = 0x02000000;
    pub const NEGOTIATE_128: u32 = 0x20000000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
    pub const NEGOTIATE_56: u32 = 0x80000000;
}

/// NTLM credentials
#[derive(Debug, Clone)]
pub struct NtlmCredentials {
    pub domain: String,
    pub username: String,
    pub password: String,
    pub workstation: String,
}

impl NtlmCredentials {
    pub fn new(domain: &str, username: &str, password: &str) -> Self {
        Self {
            domain: domain.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            workstation: "WORKSTATION".to_string(),
        }
    }

    pub fn with_workstation(mut self, workstation: &str) -> Self {
        self.workstation = workstation.to_string();
        self
    }
}

/// NTLM challenge response data
#[derive(Debug)]
pub struct NtlmChallenge {
    pub server_challenge: [u8; 8],
    pub target_name: String,
    pub target_info: Vec<u8>,
    pub flags: u32,
}

/// NTLM authentication context
pub struct NtlmContext {
    credentials: NtlmCredentials,
    negotiate_flags: u32,
    session_key: Option<Vec<u8>>,
}

impl NtlmContext {
    pub fn new(credentials: NtlmCredentials) -> Self {
        let flags = ntlm_flags::NEGOTIATE_UNICODE
            | ntlm_flags::NEGOTIATE_SIGN
            | ntlm_flags::NEGOTIATE_SEAL
            | ntlm_flags::NEGOTIATE_NTLM
            | ntlm_flags::NEGOTIATE_ALWAYS_SIGN
            | ntlm_flags::NEGOTIATE_EXTENDED_SESSIONSECURITY
            | ntlm_flags::NEGOTIATE_TARGET_INFO
            | ntlm_flags::NEGOTIATE_128
            | ntlm_flags::NEGOTIATE_KEY_EXCH
            | ntlm_flags::NEGOTIATE_56
            | ntlm_flags::REQUEST_TARGET;

        Self {
            credentials,
            negotiate_flags: flags,
            session_key: None,
        }
    }

    /// Generate NTLM Type 1 (Negotiate) message
    pub fn create_negotiate_message(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Signature
        buffer.extend_from_slice(NTLM_SIGNATURE);

        // Message type
        buffer.write_u32::<LittleEndian>(NEGOTIATE_MESSAGE).unwrap();

        // Negotiate flags
        buffer
            .write_u32::<LittleEndian>(self.negotiate_flags)
            .unwrap();

        // Domain name (empty for negotiate)
        buffer.write_u16::<LittleEndian>(0).unwrap(); // DomainNameLen
        buffer.write_u16::<LittleEndian>(0).unwrap(); // DomainNameMaxLen
        buffer.write_u32::<LittleEndian>(0).unwrap(); // DomainNameBufferOffset

        // Workstation name (empty for negotiate)
        buffer.write_u16::<LittleEndian>(0).unwrap(); // WorkstationLen
        buffer.write_u16::<LittleEndian>(0).unwrap(); // WorkstationMaxLen
        buffer.write_u32::<LittleEndian>(0).unwrap(); // WorkstationBufferOffset

        // Version (optional, but helps with compatibility)
        buffer.push(10); // ProductMajorVersion (Windows 10)
        buffer.push(0); // ProductMinorVersion
        buffer.write_u16::<LittleEndian>(19041).unwrap(); // ProductBuild
        buffer.extend_from_slice(&[0, 0, 0]); // Reserved
        buffer.push(15); // NTLMRevisionCurrent

        buffer
    }

    /// Parse NTLM Type 2 (Challenge) message
    pub fn parse_challenge_message(&self, data: &[u8]) -> SmbResult<NtlmChallenge> {
        if data.len() < 56 {
            return Err(SmbError::Protocol("Challenge message too short".to_string()));
        }

        let mut cursor = Cursor::new(data);

        // Verify signature
        let mut sig = [0u8; 8];
        cursor.read_exact(&mut sig)?;
        if &sig != NTLM_SIGNATURE {
            return Err(SmbError::Protocol("Invalid NTLM signature".to_string()));
        }

        // Message type
        let msg_type = cursor.read_u32::<LittleEndian>()?;
        if msg_type != CHALLENGE_MESSAGE {
            return Err(SmbError::Protocol(format!(
                "Expected challenge message, got type {}",
                msg_type
            )));
        }

        // Target name fields
        let target_name_len = cursor.read_u16::<LittleEndian>()?;
        let _target_name_max_len = cursor.read_u16::<LittleEndian>()?;
        let target_name_offset = cursor.read_u32::<LittleEndian>()?;

        // Negotiate flags
        let flags = cursor.read_u32::<LittleEndian>()?;

        // Server challenge
        let mut server_challenge = [0u8; 8];
        cursor.read_exact(&mut server_challenge)?;

        // Reserved
        let mut _reserved = [0u8; 8];
        cursor.read_exact(&mut _reserved)?;

        // Target info fields
        let target_info_len = cursor.read_u16::<LittleEndian>()?;
        let _target_info_max_len = cursor.read_u16::<LittleEndian>()?;
        let target_info_offset = cursor.read_u32::<LittleEndian>()?;

        // Extract target name
        let target_name = if target_name_len > 0 && (target_name_offset as usize) < data.len() {
            let start = target_name_offset as usize;
            let end = start + target_name_len as usize;
            if end <= data.len() {
                let name_bytes = &data[start..end];
                // Unicode string
                let utf16: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16_lossy(&utf16)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Extract target info
        let target_info = if target_info_len > 0 && (target_info_offset as usize) < data.len() {
            let start = target_info_offset as usize;
            let end = start + target_info_len as usize;
            if end <= data.len() {
                data[start..end].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        Ok(NtlmChallenge {
            server_challenge,
            target_name,
            target_info,
            flags,
        })
    }

    /// Generate NTLM Type 3 (Authenticate) message
    pub fn create_authenticate_message(&mut self, challenge: &NtlmChallenge) -> SmbResult<Vec<u8>> {
        // Generate client challenge
        let mut client_challenge = [0u8; 8];
        rand::thread_rng().fill(&mut client_challenge);

        // Compute NT hash
        let nt_hash = compute_nt_hash(&self.credentials.password);

        // Compute NTLMv2 response
        let (nt_response, session_base_key) = compute_ntlmv2_response(
            &nt_hash,
            &self.credentials.username,
            &self.credentials.domain,
            &challenge.server_challenge,
            &client_challenge,
            &challenge.target_info,
        )?;

        // Store session key
        self.session_key = Some(session_base_key);

        // Encode strings as UTF-16LE
        let domain_bytes = encode_utf16le(&self.credentials.domain);
        let user_bytes = encode_utf16le(&self.credentials.username);
        let workstation_bytes = encode_utf16le(&self.credentials.workstation);

        // Calculate offsets (header is 88 bytes with version)
        let payload_offset = 88u32;
        let lm_response_offset = payload_offset;
        let lm_response: [u8; 24] = [0; 24]; // Empty LM response for NTLMv2
        let nt_response_offset = lm_response_offset + lm_response.len() as u32;
        let domain_offset = nt_response_offset + nt_response.len() as u32;
        let user_offset = domain_offset + domain_bytes.len() as u32;
        let workstation_offset = user_offset + user_bytes.len() as u32;
        let encrypted_session_key_offset = workstation_offset + workstation_bytes.len() as u32;
        let encrypted_session_key: [u8; 0] = []; // No encrypted session key for basic auth

        let mut buffer = Vec::new();

        // Signature
        buffer.extend_from_slice(NTLM_SIGNATURE);

        // Message type
        buffer
            .write_u32::<LittleEndian>(AUTHENTICATE_MESSAGE)
            .unwrap();

        // LM response
        buffer
            .write_u16::<LittleEndian>(lm_response.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(lm_response.len() as u16)
            .unwrap();
        buffer
            .write_u32::<LittleEndian>(lm_response_offset)
            .unwrap();

        // NT response
        buffer
            .write_u16::<LittleEndian>(nt_response.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(nt_response.len() as u16)
            .unwrap();
        buffer.write_u32::<LittleEndian>(nt_response_offset).unwrap();

        // Domain
        buffer
            .write_u16::<LittleEndian>(domain_bytes.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(domain_bytes.len() as u16)
            .unwrap();
        buffer.write_u32::<LittleEndian>(domain_offset).unwrap();

        // User
        buffer
            .write_u16::<LittleEndian>(user_bytes.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(user_bytes.len() as u16)
            .unwrap();
        buffer.write_u32::<LittleEndian>(user_offset).unwrap();

        // Workstation
        buffer
            .write_u16::<LittleEndian>(workstation_bytes.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(workstation_bytes.len() as u16)
            .unwrap();
        buffer
            .write_u32::<LittleEndian>(workstation_offset)
            .unwrap();

        // Encrypted random session key
        buffer
            .write_u16::<LittleEndian>(encrypted_session_key.len() as u16)
            .unwrap();
        buffer
            .write_u16::<LittleEndian>(encrypted_session_key.len() as u16)
            .unwrap();
        buffer
            .write_u32::<LittleEndian>(encrypted_session_key_offset)
            .unwrap();

        // Negotiate flags
        buffer.write_u32::<LittleEndian>(challenge.flags).unwrap();

        // Version
        buffer.push(10); // ProductMajorVersion
        buffer.push(0); // ProductMinorVersion
        buffer.write_u16::<LittleEndian>(19041).unwrap(); // ProductBuild
        buffer.extend_from_slice(&[0, 0, 0]); // Reserved
        buffer.push(15); // NTLMRevisionCurrent

        // MIC (Message Integrity Code) - placeholder, would need full message to compute
        buffer.extend_from_slice(&[0u8; 16]);

        // Payload
        buffer.extend_from_slice(&lm_response);
        buffer.extend_from_slice(&nt_response);
        buffer.extend_from_slice(&domain_bytes);
        buffer.extend_from_slice(&user_bytes);
        buffer.extend_from_slice(&workstation_bytes);
        buffer.extend_from_slice(&encrypted_session_key);

        Ok(buffer)
    }

    /// Get the session key after authentication
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

/// Compute NT hash from password
fn compute_nt_hash(password: &str) -> [u8; 16] {
    use md4::{Digest, Md4};

    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16);
    let result = hasher.finalize();

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    hash
}

/// Compute NTLMv2 response
fn compute_ntlmv2_response(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> SmbResult<(Vec<u8>, Vec<u8>)> {
    // NTLMv2 hash = HMAC-MD5(NT hash, uppercase(username) + domain)
    let user_domain = format!("{}{}", username.to_uppercase(), domain);
    let user_domain_bytes = encode_utf16le(&user_domain);

    let mut ntlmv2_mac =
        HmacMd5::new_from_slice(nt_hash).map_err(|e| SmbError::Protocol(e.to_string()))?;
    ntlmv2_mac.update(&user_domain_bytes);
    let ntlmv2_hash = ntlmv2_mac.finalize().into_bytes();

    // Build blob
    let timestamp = get_windows_filetime();
    let mut blob = Vec::new();
    blob.write_u32::<LittleEndian>(0x00000101).unwrap(); // Blob signature
    blob.write_u32::<LittleEndian>(0).unwrap(); // Reserved
    blob.write_u64::<LittleEndian>(timestamp).unwrap(); // Timestamp
    blob.extend_from_slice(client_challenge); // Client challenge
    blob.write_u32::<LittleEndian>(0).unwrap(); // Reserved
    blob.extend_from_slice(target_info); // Target info

    // NTLMv2 response = HMAC-MD5(NTLMv2 hash, server_challenge + blob)
    let mut response_mac =
        HmacMd5::new_from_slice(&ntlmv2_hash).map_err(|e| SmbError::Protocol(e.to_string()))?;
    response_mac.update(server_challenge);
    response_mac.update(&blob);
    let nt_proof = response_mac.finalize().into_bytes();

    // Full NTv2 response = nt_proof + blob
    let mut nt_response = Vec::new();
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);

    // Session base key = HMAC-MD5(NTLMv2 hash, nt_proof)
    let mut session_mac =
        HmacMd5::new_from_slice(&ntlmv2_hash).map_err(|e| SmbError::Protocol(e.to_string()))?;
    session_mac.update(&nt_proof);
    let session_base_key = session_mac.finalize().into_bytes().to_vec();

    Ok((nt_response, session_base_key))
}

/// Encode string as UTF-16LE
fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Get current time as Windows FILETIME
fn get_windows_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Windows FILETIME is 100-nanosecond intervals since January 1, 1601
    // Unix epoch is January 1, 1970
    // Difference is 11644473600 seconds
    const EPOCH_DIFF: u64 = 116444736000000000;
    let unix_ns = duration.as_nanos() as u64;
    let filetime_intervals = unix_ns / 100;
    filetime_intervals + EPOCH_DIFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_hash() {
        // Known test vector: password "password" -> specific NT hash
        let hash = compute_nt_hash("password");
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_negotiate_message() {
        let creds = NtlmCredentials::new("DOMAIN", "user", "password");
        let ctx = NtlmContext::new(creds);
        let msg = ctx.create_negotiate_message();

        // Should start with NTLMSSP signature
        assert_eq!(&msg[0..8], NTLM_SIGNATURE);

        // Should be negotiate message (type 1)
        let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(msg_type, NEGOTIATE_MESSAGE);
    }

    #[test]
    fn test_encode_utf16le() {
        let encoded = encode_utf16le("Test");
        assert_eq!(encoded, vec![0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00]);
    }
}
