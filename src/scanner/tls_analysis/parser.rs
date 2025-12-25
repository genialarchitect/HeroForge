#![allow(dead_code)]
//! TLS Record and Handshake Message Parser
//!
//! This module provides parsing capabilities for TLS ClientHello and ServerHello
//! messages, extracting the fields needed for JA3/JA3S fingerprinting.
//!
//! # Supported TLS Versions
//! - TLS 1.0 (0x0301)
//! - TLS 1.1 (0x0302)
//! - TLS 1.2 (0x0303)
//! - TLS 1.3 (0x0304)
//!
//! # GREASE Handling
//! GREASE (Generate Random Extensions And Sustain Extensibility) values are
//! parsed but should be filtered out during JA3 calculation. See the main
//! module for GREASE filtering.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// TLS Record Content Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl TryFrom<u8> for ContentType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            24 => Ok(ContentType::Heartbeat),
            _ => Err(anyhow!("Unknown TLS content type: {}", value)),
        }
    }
}

/// TLS Handshake Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            3 => Ok(HandshakeType::HelloVerifyRequest),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(anyhow!("Unknown TLS handshake type: {}", value)),
        }
    }
}

/// Parsed TLS ClientHello message
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TlsClientHello {
    /// TLS version from ClientHello (as decimal, e.g., 771 for TLS 1.2)
    pub version: u16,
    /// Cipher suites offered by the client (decimal values)
    pub cipher_suites: Vec<u16>,
    /// Extensions present in ClientHello (extension type values)
    pub extensions: Vec<u16>,
    /// Elliptic curves (supported groups) offered
    pub elliptic_curves: Vec<u16>,
    /// EC point formats supported
    pub point_formats: Vec<u8>,
}

impl TlsClientHello {
    /// Create a new empty ClientHello
    pub fn new() -> Self {
        Self {
            version: 0,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            elliptic_curves: Vec::new(),
            point_formats: Vec::new(),
        }
    }
}

impl Default for TlsClientHello {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed TLS ServerHello message
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TlsServerHello {
    /// TLS version from ServerHello (as decimal)
    pub version: u16,
    /// Selected cipher suite (single value)
    pub cipher_suite: u16,
    /// Extensions present in ServerHello
    pub extensions: Vec<u16>,
}

impl TlsServerHello {
    /// Create a new empty ServerHello
    pub fn new() -> Self {
        Self {
            version: 0,
            cipher_suite: 0,
            extensions: Vec::new(),
        }
    }
}

impl Default for TlsServerHello {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS Record header
struct TlsRecordHeader {
    content_type: ContentType,
    version: u16,
    length: u16,
}

/// Parse TLS record header
fn parse_record_header(data: &[u8]) -> Result<(TlsRecordHeader, &[u8])> {
    if data.len() < 5 {
        return Err(anyhow!(
            "TLS record too short: {} bytes (need at least 5)",
            data.len()
        ));
    }

    let content_type = ContentType::try_from(data[0])?;
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]);

    let remaining = &data[5..];

    if remaining.len() < length as usize {
        return Err(anyhow!(
            "TLS record truncated: have {} bytes, need {}",
            remaining.len(),
            length
        ));
    }

    Ok((
        TlsRecordHeader {
            content_type,
            version,
            length,
        },
        &remaining[..length as usize],
    ))
}

/// Parse TLS handshake header
fn parse_handshake_header(data: &[u8]) -> Result<(HandshakeType, u32, &[u8])> {
    if data.len() < 4 {
        return Err(anyhow!(
            "TLS handshake too short: {} bytes (need at least 4)",
            data.len()
        ));
    }

    let msg_type = HandshakeType::try_from(data[0])?;
    let length = u32::from_be_bytes([0, data[1], data[2], data[3]]);

    let remaining = &data[4..];

    if remaining.len() < length as usize {
        return Err(anyhow!(
            "TLS handshake truncated: have {} bytes, need {}",
            remaining.len(),
            length
        ));
    }

    Ok((msg_type, length, &remaining[..length as usize]))
}

/// Parse a TLS ClientHello message from raw bytes
///
/// The input should be the raw TLS record containing the ClientHello,
/// starting with the record layer (content type, version, length).
///
/// # Arguments
/// * `data` - Raw bytes of the TLS ClientHello record
///
/// # Returns
/// Parsed TlsClientHello structure with all fields extracted
pub fn parse_client_hello(data: &[u8]) -> Result<TlsClientHello> {
    // Check if this is a raw TLS record or just the handshake message
    let handshake_data = if data.len() >= 5 && data[0] == 0x16 {
        // This is a full TLS record, parse the header first
        let (header, payload) = parse_record_header(data)?;

        if header.content_type != ContentType::Handshake {
            return Err(anyhow!(
                "Expected Handshake content type, got {:?}",
                header.content_type
            ));
        }

        payload
    } else {
        // Assume this is just the handshake message
        data
    };

    // Parse handshake header
    let (msg_type, _, hello_data) = parse_handshake_header(handshake_data)?;

    if msg_type != HandshakeType::ClientHello {
        return Err(anyhow!(
            "Expected ClientHello message type, got {:?}",
            msg_type
        ));
    }

    parse_client_hello_body(hello_data)
}

/// Parse the ClientHello message body (after handshake header)
fn parse_client_hello_body(data: &[u8]) -> Result<TlsClientHello> {
    let mut offset = 0;
    let mut client_hello = TlsClientHello::new();

    // Version (2 bytes)
    if offset + 2 > data.len() {
        return Err(anyhow!("ClientHello too short for version field"));
    }
    client_hello.version = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Random (32 bytes)
    if offset + 32 > data.len() {
        return Err(anyhow!("ClientHello too short for random field"));
    }
    offset += 32;

    // Session ID (1 byte length + variable)
    if offset + 1 > data.len() {
        return Err(anyhow!("ClientHello too short for session ID length"));
    }
    let session_id_len = data[offset] as usize;
    offset += 1;

    if offset + session_id_len > data.len() {
        return Err(anyhow!("ClientHello too short for session ID"));
    }
    offset += session_id_len;

    // Cipher Suites (2 bytes length + variable)
    if offset + 2 > data.len() {
        return Err(anyhow!("ClientHello too short for cipher suites length"));
    }
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + cipher_suites_len > data.len() {
        return Err(anyhow!("ClientHello too short for cipher suites"));
    }

    // Parse cipher suites (2 bytes each)
    for i in (0..cipher_suites_len).step_by(2) {
        if offset + i + 2 <= data.len() {
            let cipher = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
            client_hello.cipher_suites.push(cipher);
        }
    }
    offset += cipher_suites_len;

    // Compression Methods (1 byte length + variable)
    if offset + 1 > data.len() {
        return Err(anyhow!("ClientHello too short for compression methods"));
    }
    let compression_len = data[offset] as usize;
    offset += 1;

    if offset + compression_len > data.len() {
        return Err(anyhow!("ClientHello too short for compression methods data"));
    }
    offset += compression_len;

    // Extensions (optional, 2 bytes length + variable)
    if offset + 2 <= data.len() {
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len <= data.len() {
            parse_extensions(
                &data[offset..offset + extensions_len],
                &mut client_hello.extensions,
                Some(&mut client_hello.elliptic_curves),
                Some(&mut client_hello.point_formats),
            )?;
        }
    }

    Ok(client_hello)
}

/// Parse a TLS ServerHello message from raw bytes
///
/// The input should be the raw TLS record containing the ServerHello,
/// starting with the record layer (content type, version, length).
///
/// # Arguments
/// * `data` - Raw bytes of the TLS ServerHello record
///
/// # Returns
/// Parsed TlsServerHello structure with all fields extracted
pub fn parse_server_hello(data: &[u8]) -> Result<TlsServerHello> {
    // Check if this is a raw TLS record or just the handshake message
    let handshake_data = if data.len() >= 5 && data[0] == 0x16 {
        // This is a full TLS record, parse the header first
        let (header, payload) = parse_record_header(data)?;

        if header.content_type != ContentType::Handshake {
            return Err(anyhow!(
                "Expected Handshake content type, got {:?}",
                header.content_type
            ));
        }

        payload
    } else {
        // Assume this is just the handshake message
        data
    };

    // Parse handshake header
    let (msg_type, _, hello_data) = parse_handshake_header(handshake_data)?;

    if msg_type != HandshakeType::ServerHello {
        return Err(anyhow!(
            "Expected ServerHello message type, got {:?}",
            msg_type
        ));
    }

    parse_server_hello_body(hello_data)
}

/// Parse the ServerHello message body (after handshake header)
fn parse_server_hello_body(data: &[u8]) -> Result<TlsServerHello> {
    let mut offset = 0;
    let mut server_hello = TlsServerHello::new();

    // Version (2 bytes)
    if offset + 2 > data.len() {
        return Err(anyhow!("ServerHello too short for version field"));
    }
    server_hello.version = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Random (32 bytes)
    if offset + 32 > data.len() {
        return Err(anyhow!("ServerHello too short for random field"));
    }
    offset += 32;

    // Session ID (1 byte length + variable) - TLS 1.2 and earlier
    // In TLS 1.3, this is still present for compatibility but may be empty
    if offset + 1 > data.len() {
        return Err(anyhow!("ServerHello too short for session ID length"));
    }
    let session_id_len = data[offset] as usize;
    offset += 1;

    if offset + session_id_len > data.len() {
        return Err(anyhow!("ServerHello too short for session ID"));
    }
    offset += session_id_len;

    // Cipher Suite (2 bytes - single suite)
    if offset + 2 > data.len() {
        return Err(anyhow!("ServerHello too short for cipher suite"));
    }
    server_hello.cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // Compression Method (1 byte)
    if offset + 1 > data.len() {
        return Err(anyhow!("ServerHello too short for compression method"));
    }
    offset += 1;

    // Extensions (optional, 2 bytes length + variable)
    if offset + 2 <= data.len() {
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len <= data.len() {
            parse_extensions(
                &data[offset..offset + extensions_len],
                &mut server_hello.extensions,
                None,
                None,
            )?;
        }
    }

    // Check for TLS 1.3 via supported_versions extension
    // In TLS 1.3, the version field in the record is always 0x0303 (TLS 1.2)
    // but the actual version is indicated in the supported_versions extension
    // For JA3S, we use the version from the hello message, not the extension

    Ok(server_hello)
}

/// Parse TLS extensions from a byte slice
fn parse_extensions(
    data: &[u8],
    extension_types: &mut Vec<u16>,
    mut elliptic_curves: Option<&mut Vec<u16>>,
    mut point_formats: Option<&mut Vec<u8>>,
) -> Result<()> {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + ext_len > data.len() {
            break; // Truncated extension, stop parsing
        }

        extension_types.push(ext_type);

        // Parse specific extensions we care about
        match ext_type {
            // Supported Groups (Elliptic Curves) - extension type 10 (0x000a)
            0x000a => {
                if let Some(ref mut curves) = elliptic_curves {
                    if ext_len >= 2 {
                        let curves_len =
                            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                        let curves_data = &data[offset + 2..offset + 2 + curves_len.min(ext_len - 2)];

                        for i in (0..curves_data.len()).step_by(2) {
                            if i + 2 <= curves_data.len() {
                                let curve = u16::from_be_bytes([curves_data[i], curves_data[i + 1]]);
                                curves.push(curve);
                            }
                        }
                    }
                }
            }

            // EC Point Formats - extension type 11 (0x000b)
            0x000b => {
                if let Some(ref mut formats) = point_formats {
                    if ext_len >= 1 {
                        let formats_len = data[offset] as usize;
                        let formats_data = &data[offset + 1..offset + 1 + formats_len.min(ext_len - 1)];

                        for &format in formats_data {
                            formats.push(format);
                        }
                    }
                }
            }

            _ => {}
        }

        offset += ext_len;
    }

    Ok(())
}

/// Extract just the handshake message from a full TLS record
/// Useful when you have captured traffic and need to separate multiple messages
pub fn extract_handshake_message(data: &[u8]) -> Result<(HandshakeType, Vec<u8>)> {
    let handshake_data = if data.len() >= 5 && data[0] == 0x16 {
        let (_, payload) = parse_record_header(data)?;
        payload
    } else {
        data
    };

    let (msg_type, length, msg_data) = parse_handshake_header(handshake_data)?;
    Ok((msg_type, msg_data[..length as usize].to_vec()))
}

/// Check if data looks like a TLS ClientHello
pub fn is_client_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }

    // Check for TLS record layer
    if data[0] != 0x16 {
        return false;
    }

    // Check version (should be 0x0301-0x0304 or legacy 0x0300)
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0300 || version > 0x0304 {
        return false;
    }

    // Check handshake type is ClientHello (0x01)
    data.len() >= 6 && data[5] == 0x01
}

/// Check if data looks like a TLS ServerHello
pub fn is_server_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }

    // Check for TLS record layer
    if data[0] != 0x16 {
        return false;
    }

    // Check version
    let version = u16::from_be_bytes([data[1], data[2]]);
    if version < 0x0300 || version > 0x0304 {
        return false;
    }

    // Check handshake type is ServerHello (0x02)
    data.len() >= 6 && data[5] == 0x02
}

/// Get the TLS version from a record without full parsing
pub fn get_record_version(data: &[u8]) -> Option<u16> {
    if data.len() >= 3 {
        Some(u16::from_be_bytes([data[1], data[2]]))
    } else {
        None
    }
}

/// Get the handshake version from a ClientHello/ServerHello without full parsing
pub fn get_handshake_version(data: &[u8]) -> Option<u16> {
    let offset = if data.len() >= 5 && data[0] == 0x16 {
        5 + 4 // Skip record header + handshake header
    } else if data.len() >= 4 {
        4 // Skip just handshake header
    } else {
        return None;
    };

    if data.len() >= offset + 2 {
        Some(u16::from_be_bytes([data[offset], data[offset + 1]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example TLS 1.2 ClientHello (minimal)
    fn create_minimal_client_hello() -> Vec<u8> {
        let mut data = Vec::new();

        // TLS Record Header
        data.push(0x16); // Content type: Handshake
        data.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0

        // Handshake message (to be filled)
        let mut handshake = Vec::new();

        // Handshake Header
        handshake.push(0x01); // Type: ClientHello

        // ClientHello body (to be filled)
        let mut hello = Vec::new();

        // Version: TLS 1.2
        hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID length: 0
        hello.push(0x00);

        // Cipher Suites length: 4 (2 cipher suites)
        hello.extend_from_slice(&[0x00, 0x04]);
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression methods length: 1
        hello.push(0x01);
        hello.push(0x00); // null compression

        // Extensions length
        let mut extensions = Vec::new();

        // SNI extension (type 0x0000)
        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type
        extensions.extend_from_slice(&[0x00, 0x00]); // Extension length (empty for test)

        // Supported groups extension (type 0x000a)
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length
        extensions.extend_from_slice(&[0x00, 0x02]); // Supported groups length
        extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1

        // EC point formats extension (type 0x000b)
        extensions.extend_from_slice(&[0x00, 0x0b]); // Extension type
        extensions.extend_from_slice(&[0x00, 0x02]); // Extension length
        extensions.push(0x01); // Point formats length
        extensions.push(0x00); // uncompressed

        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Add length to handshake header (3 bytes)
        let hello_len = hello.len() as u32;
        handshake.push((hello_len >> 16) as u8);
        handshake.push((hello_len >> 8) as u8);
        handshake.push(hello_len as u8);
        handshake.extend_from_slice(&hello);

        // Add record length
        let record_len = handshake.len() as u16;
        data.extend_from_slice(&record_len.to_be_bytes());
        data.extend_from_slice(&handshake);

        data
    }

    // Example TLS 1.2 ServerHello (minimal)
    fn create_minimal_server_hello() -> Vec<u8> {
        let mut data = Vec::new();

        // TLS Record Header
        data.push(0x16); // Content type: Handshake
        data.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2

        // Handshake message
        let mut handshake = Vec::new();
        handshake.push(0x02); // Type: ServerHello

        // ServerHello body
        let mut hello = Vec::new();

        // Version: TLS 1.2
        hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID length: 0
        hello.push(0x00);

        // Cipher Suite: TLS_AES_128_GCM_SHA256
        hello.extend_from_slice(&[0x13, 0x01]);

        // Compression method: null
        hello.push(0x00);

        // Extensions
        let mut extensions = Vec::new();

        // Renegotiation info extension
        extensions.extend_from_slice(&[0xff, 0x01]); // Extension type
        extensions.extend_from_slice(&[0x00, 0x01]); // Extension length
        extensions.push(0x00); // Empty renegotiation info

        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        // Add length to handshake header
        let hello_len = hello.len() as u32;
        handshake.push((hello_len >> 16) as u8);
        handshake.push((hello_len >> 8) as u8);
        handshake.push(hello_len as u8);
        handshake.extend_from_slice(&hello);

        // Add record length
        let record_len = handshake.len() as u16;
        data.extend_from_slice(&record_len.to_be_bytes());
        data.extend_from_slice(&handshake);

        data
    }

    #[test]
    fn test_parse_client_hello() {
        let data = create_minimal_client_hello();
        let result = parse_client_hello(&data);

        assert!(result.is_ok());
        let client_hello = result.unwrap();

        assert_eq!(client_hello.version, 0x0303); // TLS 1.2
        assert_eq!(client_hello.cipher_suites.len(), 2);
        assert!(client_hello.cipher_suites.contains(&0x1301));
        assert!(client_hello.cipher_suites.contains(&0xc02f));
        assert!(!client_hello.extensions.is_empty());
        assert!(client_hello.elliptic_curves.contains(&0x0017)); // secp256r1
        assert!(client_hello.point_formats.contains(&0)); // uncompressed
    }

    #[test]
    fn test_parse_server_hello() {
        let data = create_minimal_server_hello();
        let result = parse_server_hello(&data);

        assert!(result.is_ok());
        let server_hello = result.unwrap();

        assert_eq!(server_hello.version, 0x0303); // TLS 1.2
        assert_eq!(server_hello.cipher_suite, 0x1301);
        assert!(!server_hello.extensions.is_empty());
    }

    #[test]
    fn test_is_client_hello() {
        let client_hello = create_minimal_client_hello();
        let server_hello = create_minimal_server_hello();

        assert!(is_client_hello(&client_hello));
        assert!(!is_client_hello(&server_hello));
        assert!(!is_client_hello(&[0x00, 0x01, 0x02])); // Too short
    }

    #[test]
    fn test_is_server_hello() {
        let client_hello = create_minimal_client_hello();
        let server_hello = create_minimal_server_hello();

        assert!(is_server_hello(&server_hello));
        assert!(!is_server_hello(&client_hello));
        assert!(!is_server_hello(&[0x00, 0x01, 0x02])); // Too short
    }

    #[test]
    fn test_get_versions() {
        let client_hello = create_minimal_client_hello();

        let record_version = get_record_version(&client_hello);
        assert_eq!(record_version, Some(0x0301)); // TLS 1.0 in record layer

        let handshake_version = get_handshake_version(&client_hello);
        assert_eq!(handshake_version, Some(0x0303)); // TLS 1.2 in hello
    }

    #[test]
    fn test_content_type_conversion() {
        assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
        assert_eq!(ContentType::try_from(21).unwrap(), ContentType::Alert);
        assert!(ContentType::try_from(99).is_err());
    }

    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(
            HandshakeType::try_from(1).unwrap(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            HandshakeType::try_from(2).unwrap(),
            HandshakeType::ServerHello
        );
        assert!(HandshakeType::try_from(99).is_err());
    }
}
